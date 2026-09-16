using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Json = System.Text.Json.JsonSerializer;

namespace FrostAuth;

public sealed class FrostAuthClient
{
    public const string SdkVersion = "1.0.0";
    public const string DefaultBaseUrl = "https://api.frostauth.cc";
    private const long MaxSignatureSkewMs = 60_000;
    private const int MaxRetryAfterSeconds = 10;
    private const string AssertionPrefix = "frostauth:assertion:v1";

    public static readonly IReadOnlyDictionary<string, string> PublicKeys = new Dictionary<string, string> { ["k2"] = "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo" };

    private readonly string _owner, _product, _version, _baseUrl;
    private readonly TimeSpan _timeout;
    private readonly int _retries;
    private readonly long _offlineGraceSeconds;
    private readonly bool _allowInsecure, _allowPrivateDns, _collectHardware;
    private readonly string? _hwOverride;
    private readonly HttpClient _http;
    private readonly object _lock = new();

    private Dictionary<string, byte[]> _keys = new();
    private JsonElement _app;
    private JsonElement _license, _productInfo, _device, _account;
    private string? _user;
    private List<JsonElement> _subscriptions = new();
    private JsonElement? _session;
    private string? _storedKey, _assertion, _offlineUntil, _machineId;
    private DateTime? _offlineSince;
    private bool _initialized, _activated, _closed;

    public event Action<JsonElement>? Activated;
    public event Action<JsonElement>? LoggedIn;
    public event Action<JsonElement>? Validated;
    public event Action<string, string>? UpdateAvailable;
    public event Action<FrostAuthError, long, bool>? Offline;
    public event Action<FrostAuthError>? Invalid;
    public event Action<FrostAuthError>? NeedsActivation;

    private FrostAuthClient(Options o)
    {
        _owner = o.Owner; _product = o.Product; _version = o.Version;
        _baseUrl = string.IsNullOrWhiteSpace(o.BaseUrl) ? DefaultBaseUrl : o.BaseUrl;
        _timeout = o.Timeout ?? TimeSpan.FromSeconds(10);
        _retries = o.Retries ?? 2;
        _offlineGraceSeconds = o.OfflineGraceSeconds ?? 900;
        _allowInsecure = o.AllowInsecure;
        _allowPrivateDns = o.AllowPrivateDns;
        _collectHardware = o.CollectHardware ?? true;
        _hwOverride = o.HardwareIdOverride;

        var uri = new Uri(_baseUrl);
        var host = uri.Host;
        var loopback = host is "localhost" or "127.0.0.1" or "::1";
        if (uri.Scheme != "https" && !loopback && !_allowInsecure)
        {
            throw new FrostAuthError("Refusing to send a licence key over plain http. Use https, or pass AllowInsecure=true if you know what you are doing.", FrostAuthError.Codes.Config);
        }
        _http = new HttpClient { Timeout = _timeout, BaseAddress = new Uri(_baseUrl) };
    }

    public sealed class Options
    {
        public required string Owner { get; init; }
        public required string Product { get; init; }
        public required string Version { get; init; }
        public string? BaseUrl { get; init; }
        public TimeSpan? Timeout { get; init; }
        public int? Retries { get; init; }
        public long? OfflineGraceSeconds { get; init; }
        public bool AllowInsecure { get; init; }
        public bool AllowPrivateDns { get; init; }
        public string? HardwareIdOverride { get; init; }
        public bool? CollectHardware { get; init; }
    }

    public static FrostAuthClient Create(Options o)
    {
        foreach (var (name, v) in new[] { ("owner", o.Owner), ("product", o.Product), ("version", o.Version) })
        {
            if (string.IsNullOrWhiteSpace(v)) throw new FrostAuthError($"{name} is required", FrostAuthError.Codes.Config);
        }
        return new FrostAuthClient(o);
    }

    public async Task<JsonElement> InitAsync()
    {
        await AssertRealHostAsync().ConfigureAwait(false);
        var path = $"/api/v1/settings/catalog/{Uri.EscapeDataString(_owner)}/{Uri.EscapeDataString(_product)}";
        var body = await SendRawAsync(HttpMethod.Get, path).ConfigureAwait(false);
        if (!body.TryGetProperty("success", out var ok) || ok.ValueKind != JsonValueKind.True)
        {
            var code = body.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString()! : "APP_NOT_FOUND";
            var msg = body.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString()! : "Application not found";
            throw new FrostAuthError(msg, code, 404);
        }
        var keyId = body.TryGetProperty("key_id", out var kid) ? kid.GetString() ?? "" : "";
        var served = body.TryGetProperty("public_key", out var pk) ? pk.GetString() ?? "" : "";
        if (!PublicKeys.TryGetValue(keyId, out var pinned) || served != pinned)
        {
            throw new FrostAuthError("Server identity check failed — refusing to continue", FrostAuthError.Codes.Signature, 401);
        }
        lock (_lock)
        {
            _keys = new Dictionary<string, byte[]> { [keyId] = SpkiToRaw(pinned) };
            _app = body.Clone();
            _initialized = true;
        }
        return Snapshot();
    }

    public Task<JsonElement> ActivateAsync(string key, string? buildHash = null, string? label = null) =>
        CredentialCallAsync("/api/v1/activate", key, username: null, password: null, buildHash, label);

    public Task<JsonElement> RegisterAsync(string key, string username, string password,
        string? buildHash = null, string? label = null) =>
        CredentialCallAsync("/api/v1/sdk/register", key, username, password, buildHash, label);

    public async Task<JsonElement> LoginAsync(string username, string password,
        string? twofa = null, string? buildHash = null, string? label = null)
    {
        RequireInit();
        var body = BuildLoginBody(username, password, twofa, buildHash, label);
        var data = await RequestEnvelopeAsync(HttpMethod.Post, "/api/v1/sdk/login", body).ConfigureAwait(false);
        AdoptAndActivate(data);
        LoggedIn?.Invoke(Snapshot());
        return Snapshot();
    }

    public Task<JsonElement> UpgradeAsync(string username, string password, string key)
    {
        RequireInit();
        return RequestEnvelopeAsync(HttpMethod.Post, "/api/v1/sdk/upgrade", new Dictionary<string, object?>
        {
            ["owner"] = _owner, ["product"] = _product,
            ["username"] = username.Trim(), ["password"] = password, ["key"] = key.Trim(),
        });
    }

    public async Task<JsonElement> LogoutAsync()
    {
        bool had;
        lock (_lock) had = Token() is not null;
        try
        {
            return had ? await AuthedAsync(HttpMethod.Post, "/api/v1/sdk/logout", null).ConfigureAwait(false) : Json.Deserialize<JsonElement>("{\"signedOut\":true}");
        }
        finally { Close(); }
    }

    public async Task<JsonElement> SessionAsync()
    {
        var data = await AuthedAsync(HttpMethod.Get, "/api/v1/sdk/session", null).ConfigureAwait(false);
        lock (_lock) Adopt(data);
        return Snapshot();
    }

    public async Task<string?> VariableAsync(string key)
    {
        var d = await AuthedAsync(HttpMethod.Get, $"/api/v1/sdk/vars/app/{Uri.EscapeDataString(key)}", null).ConfigureAwait(false);
        return d.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    public async Task<string?> GetVarAsync(string key)
    {
        var d = await AuthedAsync(HttpMethod.Get, $"/api/v1/sdk/vars/user/{Uri.EscapeDataString(key)}", null).ConfigureAwait(false);
        return d.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }

    public async Task<string[]> ListVarsAsync()
    {
        var d = await AuthedAsync(HttpMethod.Get, "/api/v1/sdk/vars/user", null).ConfigureAwait(false);
        if (d.TryGetProperty("variables", out var vars) && vars.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var v in vars.EnumerateArray())
            {
                if (v.TryGetProperty("key", out var k) && k.ValueKind == JsonValueKind.String)
                    list.Add(k.GetString()!);
            }
            return list.ToArray();
        }
        return Array.Empty<string>();
    }

    public Task<JsonElement> SetVarAsync(string key, string value) =>
        AuthedAsync(HttpMethod.Put, $"/api/v1/sdk/vars/user/{Uri.EscapeDataString(key)}",
            new Dictionary<string, object?> { ["value"] = value ?? "" });

    public async Task<JsonElement> ChangeUsernameAsync(string username, string password)
    {
        return await AuthedAsync(HttpMethod.Patch, "/api/v1/sdk/username",
            new Dictionary<string, object?> { ["username"] = username.Trim(), ["password"] = password }).ConfigureAwait(false);
    }

    public Task<JsonElement> LogAsync(string message) =>
        AuthedAsync(HttpMethod.Post, "/api/v1/sdk/log",
            new Dictionary<string, object?> { ["message"] = Trunc(message ?? "", 256) });

    public async Task<JsonElement> BanAsync(string reason = "")
    {
        try
        {
            return await AuthedAsync(HttpMethod.Post, "/api/v1/sdk/ban",
                new Dictionary<string, object?> { ["reason"] = Trunc(reason ?? "", 200) }).ConfigureAwait(false);
        }
        finally
        {
            StopHeartbeat();
            lock (_lock) { _activated = false; _assertion = null; _offlineUntil = null; }
        }
    }

    public Task<JsonElement> FetchOnlineAsync() => AuthedAsync(HttpMethod.Get, "/api/v1/sdk/online", null);
    public Task<JsonElement> CheckBlacklistAsync() => AuthedAsync(HttpMethod.Get, "/api/v1/sdk/checkblacklist", null);
    public Task<JsonElement> AppDataAsync() => AuthedAsync(HttpMethod.Get, "/api/v1/sdk/app", null);

    public Task<byte[]> FileAsync(string fileId) => throw new FrostAuthError("File downloads are disabled on this server");

    public Task<JsonElement> WebhookAsync(string webId, string? parameters = null, string? body = null, string? contentType = null)
    {
        if (string.IsNullOrWhiteSpace(webId))
            throw new FrostAuthError("webhook id is required", FrostAuthError.Codes.Config);
        var payload = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(parameters)) payload["params"] = Trunc(parameters, 2048);
        if (!string.IsNullOrEmpty(body)) payload["body"] = Trunc(body, 8192);
        if (!string.IsNullOrEmpty(contentType)) payload["conttype"] = Trunc(contentType, 128);
        return AuthedAsync(HttpMethod.Post, $"/api/v1/sdk/webhook/{Uri.EscapeDataString(webId)}", payload);
    }

    public async Task<JsonElement> ValidateAsync()
    {
        RequireInit();
        bool hasCred;
        lock (_lock) hasCred = Token() is not null || _storedKey is not null;
        if (!hasCred) throw new FrostAuthError("Activate before validating", FrostAuthError.Codes.NotActivated);

        try
        {
            var data = await SendValidateAsync().ConfigureAwait(false);
            AdoptAndActivate(data);
            return Snapshot();
        }
        catch (FrostAuthError err)
        {
            var stale = err.Code is "INVALID_TOKEN" or "INVALID_SESSION";
            string? key;
            lock (_lock) key = _storedKey;
            if (stale && key is not null)
            {
                lock (_lock) _session = null;
                var data = await SendValidateAsync().ConfigureAwait(false);
                AdoptAndActivate(data);
                return Snapshot();
            }
            throw;
        }
    }

    private System.Threading.Timer? _heartbeat;

    public void StartHeartbeat(int? intervalSeconds = null)
    {
        bool hasCred;
        lock (_lock) hasCred = Token() is not null || _storedKey is not null;
        if (!hasCred)
        {
            throw new FrostAuthError("Nothing to heartbeat with: activate with a licence key, or sign in on a plan that issues session tokens.", FrostAuthError.Codes.NotActivated);
        }
        lock (_lock) _closed = false;
        StopHeartbeat();
        int periodMs = intervalSeconds is { } s ? Math.Max(1, s) * 1000 : PeriodFromSession();
        _heartbeat = new System.Threading.Timer(async _ =>
        {
            try { await ValidateAsync().ConfigureAwait(false); }
            catch (FrostAuthError err)
            {
                if (err.NeedsActivation) { StopHeartbeat(); NeedsActivation?.Invoke(err); return; }
                if (err.Terminal) { StopHeartbeat(); Invalid?.Invoke(err); return; }
                long offlineFor;
                bool verified;
                lock (_lock)
                {
                    _offlineSince ??= DateTime.UtcNow;
                    offlineFor = (long)(DateTime.UtcNow - _offlineSince.Value).TotalSeconds;
                    verified = _assertion is not null && VerifyAssertion(_assertion, _keys, _machineId).Ok;
                }
                Offline?.Invoke(err, offlineFor, verified);
                if (!verified && offlineFor > _offlineGraceSeconds)
                {
                    StopHeartbeat();
                    Invalid?.Invoke(new FrostAuthError($"Could not reach the licence server for {offlineFor}s", FrostAuthError.Codes.Network));
                }
            }
        }, null, periodMs, periodMs);
    }

    private int PeriodFromSession()
    {
        long baseSeconds = 180;
        lock (_lock)
        {
            if (_session.HasValue && _session.Value.TryGetProperty("heartbeatSeconds", out var hb) && hb.TryGetInt64(out var v) && v > 0) baseSeconds = v;
        }
        return (int)Math.Max(15, baseSeconds) * 1000 + Random.Shared.Next(5000);
    }

    public void StopHeartbeat()
    {
        _heartbeat?.Dispose();
        _heartbeat = null;
    }

    public void Close()
    {
        StopHeartbeat();
        lock (_lock)
        {
            _closed = true;
            _storedKey = null;
            _session = null;
            _activated = false;
            _account = default;
            _subscriptions = new();
            _assertion = null;
            _offlineUntil = null;
            _offlineSince = null;
        }
    }

    public (bool Ok, string Reason) CheckOffline()
    {
        string? a; string? mid;
        Dictionary<string, byte[]> pins;
        lock (_lock) { a = _assertion; mid = _machineId; pins = _keys; }
        if (a is null) return (false, "no assertion issued yet");
        if (pins.Count == 0) return (false, "no pinned publicKey to verify against");
        var r = VerifyAssertion(a, pins, mid);
        return (r.Ok, r.Reason);
    }

    public JsonElement Snapshot()
    {
        lock (_lock)
        {
            var dict = new Dictionary<string, object?>
            {
                ["app"] = JsonOrNull(_app),
                ["license"] = JsonOrNull(_license),
                ["product"] = JsonOrNull(_productInfo),
                ["device"] = JsonOrNull(_device),
                ["user"] = _user,
                ["account"] = JsonOrNull(_account),
                ["subscriptions"] = _subscriptions,
                ["valid"] = _activated && !_closed,
            };
            return Json.SerializeToElement(dict);
        }
    }

    private static object? JsonOrNull(JsonElement e) => e.ValueKind == JsonValueKind.Undefined ? null : e;

    private async Task<JsonElement> CredentialCallAsync(
        string path, string key, string? username, string? password,
        string? buildHash, string? label)
    {
        RequireInit();
        if (string.IsNullOrWhiteSpace(key)) throw new FrostAuthError("licence key is required", FrostAuthError.Codes.Config);
        var body = new Dictionary<string, object?>
        {
            ["key"] = key.Trim(),
            ["hwid"] = MachineId(),
            ["os"] = OsName(),
            ["appVersion"] = _version,
        };
        if (username is not null) body["username"] = username.Trim();
        if (password is not null) body["password"] = password;
        foreach (var kv in HardwareExtra()) body[kv.Key] = kv.Value;
        if (!string.IsNullOrWhiteSpace(buildHash)) body["hash"] = buildHash;
        if (!string.IsNullOrWhiteSpace(label)) body["label"] = Trunc(label, 64);
        var data = await RequestEnvelopeAsync(HttpMethod.Post, path, body).ConfigureAwait(false);
        lock (_lock) _storedKey = key.Trim();
        AdoptAndActivate(data);
        Activated?.Invoke(Snapshot());
        return Snapshot();
    }

    private Dictionary<string, object?> BuildLoginBody(
        string username, string password, string? twofa, string? buildHash, string? label)
    {
        var body = new Dictionary<string, object?>
        {
            ["owner"] = _owner, ["product"] = _product,
            ["username"] = username.Trim(), ["password"] = password,
            ["hwid"] = MachineId(), ["os"] = OsName(), ["appVersion"] = _version,
        };
        foreach (var kv in HardwareExtra()) body[kv.Key] = kv.Value;
        if (!string.IsNullOrWhiteSpace(twofa)) body["twofa"] = twofa;
        if (!string.IsNullOrWhiteSpace(buildHash)) body["hash"] = buildHash;
        if (!string.IsNullOrWhiteSpace(label)) body["label"] = Trunc(label, 64);
        return body;
    }

    public readonly record struct AssertionResult(bool Ok, string Reason, JsonElement Claims);

    private static byte[] ClaimString(JsonElement claims)
    {
        string[] fields = { "lic", "pid", "dev", "hwid", "status", "tier", "exp", "iat", "nbf", "naf" };
        var sb = new StringBuilder(AssertionPrefix).Append("\n1");
        foreach (var f in fields)
        {
            sb.Append('\n');
            if (claims.TryGetProperty(f, out var v) && v.ValueKind == JsonValueKind.String)
                sb.Append(v.GetString());
        }
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static long? ParseMs(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.Number => v.TryGetInt64(out var n) ? n : null,
        JsonValueKind.String => DateTimeOffset.TryParse(v.GetString(), null,
            System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
            ? dt.ToUnixTimeMilliseconds()
            : null,
        _ => null,
    };

    public static AssertionResult VerifyAssertion(string assertion, IReadOnlyDictionary<string, byte[]> pins, string? hwid)
    {
        if (pins.Count == 0) return new(false, "no pinned public key", default);
        var parts = (assertion ?? "").Split('.');
        if (parts.Length != 3) return new(false, "malformed", default);
        var (payload, sigB64, keyId) = (parts[0], parts[1], parts[2]);

        var candidates = pins
            .Where(kv => string.IsNullOrWhiteSpace(keyId) || kv.Key == keyId)
            .Select(kv => kv.Value)
            .ToList();
        if (candidates.Count == 0)
            return new(false, $"signed with key \"{keyId}\", which this build does not trust", default);

        JsonElement claims;
        byte[] signature;
        try
        {
            claims = Json.Deserialize<JsonElement>(Encoding.UTF8.GetString(B64uDecode(payload)));
            signature = B64uDecode(sigB64);
        }
        catch
        {
            return new(false, "unreadable", default);
        }

        var material = ClaimString(claims);
        var ok = candidates.Any(raw => EdVerify(raw, material, signature));
        if (!ok) return new(false, "signature does not verify", claims);

        if (!string.IsNullOrEmpty(hwid))
        {
            var claimHwid = claims.TryGetProperty("hwid", out var h) && h.ValueKind == JsonValueKind.String
                ? h.GetString() : null;
            if (claimHwid != hwid) return new(false, "issued for a different machine", claims);
        }
        var nbf = claims.TryGetProperty("nbf", out var nbfV) ? ParseMs(nbfV) : null;
        var naf = claims.TryGetProperty("naf", out var nafV) ? ParseMs(nafV) : null;
        if (nbf is null || naf is null || naf <= nbf)
            return new(false, "offline window is missing or unreadable", claims);
        var at = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (at < nbf) return new(false, "not yet valid", claims);
        if (at > naf) return new(false, "offline period has run out", claims);
        if (claims.TryGetProperty("exp", out var expV) && expV.ValueKind is JsonValueKind.String or JsonValueKind.Number)
        {
            var exp = ParseMs(expV);
            if (exp is null || at > exp) return new(false, "licence expired", claims);
        }
        return new(true, "", claims);
    }

    private static byte[] B64uDecode(string s)
    {
        var t = s.Trim();
        var padded = t.PadRight(t.Length + ((4 - t.Length % 4) % 4), '=');
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    private static byte[] SpkiToRaw(string b64)
    {
        var der = B64uDecode(b64);
        if (der.Length != 44) throw new FrostAuthError("not a usable Ed25519 public key", FrostAuthError.Codes.Config);
        return der[12..];
    }

    private static bool EdVerify(byte[] raw32, byte[] message, byte[] signature)
    {
        try
        {
            var keyParams = new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(raw32, 0);
            var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            verifier.Init(false, keyParams);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }

    private static string OsName()
    {
        if (OperatingSystem.IsWindows()) return "windows";
        if (OperatingSystem.IsMacOS()) return "darwin";
        if (OperatingSystem.IsLinux()) return "linux";
        return Environment.OSVersion.Platform.ToString();
    }

    private string MachineId()
    {
        lock (_lock)
        {
            if (_machineId is not null) return _machineId;
            _machineId = string.IsNullOrWhiteSpace(_hwOverride)
                ? HardwareId(_owner)
                : _hwOverride!;
            return _machineId;
        }
    }

    public static string HardwareId(string scope)
    {
        var s = string.IsNullOrWhiteSpace(scope) ? "frostauth" : scope;
        return Sha256Hex($"{s}|{RawMachineId()}");
    }

    private static volatile string? _machineCache;

    private static string RawMachineId()
    {
        var cached = _machineCache;
        if (cached is not null) return cached;
        string? found = null;
        try
        {
            if (OperatingSystem.IsWindows())
            {
                found = QueryReg(@"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid");
            }
            else if (OperatingSystem.IsMacOS())
            {
                var outText = RunProcess("/usr/sbin/ioreg", "-rd1 -c IOPlatformExpertDevice");
                var idx = outText.IndexOf("\"IOPlatformUUID\"", StringComparison.Ordinal);
                if (idx >= 0)
                {
                    var eq = outText.IndexOf("\" = \"", idx, StringComparison.Ordinal);
                    if (eq >= 0)
                    {
                        var start = eq + 5;
                        var end = outText.IndexOf('"', start);
                        if (end > start) found = outText[start..end];
                    }
                }
            }
            else if (OperatingSystem.IsLinux())
            {
                foreach (var path in new[] { "/etc/machine-id", "/var/lib/dbus/machine-id" })
                {
                    if (File.Exists(path))
                    {
                        var v = File.ReadAllText(path).Trim();
                        if (v.Length > 0) { found = v; break; }
                    }
                }
            }
        }
        catch { }
        var id = string.IsNullOrWhiteSpace(found) ? $"fallback:{Environment.MachineName}:{Environment.UserName}:{OsName()}" : found;
        _machineCache = id;
        return id;
    }

    private static string QueryReg(string key, string valueName)
    {
        var outText = RunProcess("reg", $"query \"{key}\" /v {valueName}");
        foreach (var line in outText.Split('\n'))
        {
            var i = line.IndexOf("REG_SZ", StringComparison.Ordinal);
            if (i >= 0) return line[(i + 6)..].Trim();
        }
        return "";
    }

    private static string RunProcess(string fileName, string arguments)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p is null) return "";
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            return text;
        }
        catch { return ""; }
    }

    private static string Sha256Hex(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string Facet(string v) => Sha256Hex(v)[..32];

    private Dictionary<string, object?> HardwareExtra()
    {
        if (!_collectHardware) return new();
        try
        {
            var cpu = "unknown";
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    cpu = QueryReg(@"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString");
                    if (string.IsNullOrWhiteSpace(cpu)) cpu = "unknown";
                }
                else if (OperatingSystem.IsMacOS())
                {
                    var v = RunProcess("/usr/sbin/sysctl", "-n machdep.cpu.brand_string").Trim();
                    if (v.Length > 0) cpu = v;
                }
                else if (OperatingSystem.IsLinux() && File.Exists("/proc/cpuinfo"))
                {
                    foreach (var line in File.ReadLines("/proc/cpuinfo"))
                    {
                        if (line.StartsWith("model name"))
                        {
                            var i = line.IndexOf(':');
                            if (i >= 0) cpu = line[(i + 1)..].Trim();
                            break;
                        }
                    }
                }
            }
            catch { }

            var components = new List<object?>
            {
                new { n = "cpu", v = Facet($"{cpu}|{Environment.ProcessorCount}") },
                new { n = "ram", v = Facet("unknown") },
                new { n = "arch", v = Facet(System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString()) },
                new { n = "platform", v = Facet(OsName()) },
                new { n = "host", v = Facet(Environment.MachineName) },
            };
            var cpuIsVm = System.Text.RegularExpressions.Regex.IsMatch(cpu, @"vmware|virtualbox|vbox|qemu|kvm|xen|hyper-?v|parallels|bhyve|virtual machine|innotek", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return new Dictionary<string, object?>
            {
                ["components"] = components,
                ["virtual"] = cpuIsVm,
            };
        }
        catch { return new(); }
    }


    private async Task AssertRealHostAsync()
    {
        if (_allowPrivateDns) return;
        var host = new Uri(_baseUrl).Host;
        if (string.IsNullOrEmpty(host)) return;
        var bare = host.Trim('[', ']');
        if (bare is "localhost" or "127.0.0.1" or "::1") return;
        if (IPAddress.TryParse(bare, out _)) return;
        IPAddress[] addrs;
        try { addrs = await Dns.GetHostAddressesAsync(bare).ConfigureAwait(false); }
        catch (Exception)
        {
            throw new FrostAuthError($"Cannot resolve the licence server host \"{bare}\" — refusing to continue", FrostAuthError.Codes.Network);
        }
        var privateAddrs = addrs.Where(IsPrivate).Select(a => a.ToString()).Distinct().ToList();
        if (privateAddrs.Count > 0)
        {
            throw new FrostAuthError(
                $"\"{bare}\" resolves to loopback or private space ({string.Join(", ", privateAddrs)}) — " +
                "this is what a hosts-file hijack or licence emulator looks like. Refusing to continue.",
                FrostAuthError.Codes.Network);
        }
    }

    private static bool IsPrivate(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] == 10
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 169 && bytes[1] == 254)
                || bytes[0] == 0;
        }
        if (bytes.Length == 16)
        {
            return bytes[0] is 0xfc or 0xfd                                // ULA
                || (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)         // link-local
                || (bytes[0] == 0 && bytes[1] == 0);                       // unspecified
        }
        return false;
    }

    private void RequireInit()
    {
        lock (_lock)
        {
            if (!_initialized) throw new FrostAuthError("Call InitAsync() before anything else", FrostAuthError.Codes.NotInitialized);
        }
    }

    private string? Token()
    {
        if (_session is not { } s || s.ValueKind != JsonValueKind.Object) return null;
        return s.TryGetProperty("token", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null;
    }

    private async Task<JsonElement> AuthedAsync(HttpMethod method, string path, Dictionary<string, object?>? body)
    {
        string? t;
        lock (_lock) t = Token();
        if (string.IsNullOrEmpty(t))
            throw new FrostAuthError("This call needs a session — activate or sign in first", FrostAuthError.Codes.NotActivated);
        return await RequestEnvelopeAsync(method, path, body, t).ConfigureAwait(false);
    }

    private void AdoptAndActivate(JsonElement data)
    {
        lock (_lock)
        {
            Adopt(data);
            _activated = true;
            _offlineSince = null;
        }
    }

    private void Adopt(JsonElement data)
    {
        if (data.ValueKind != JsonValueKind.Object) return;
        if (data.TryGetProperty("session", out var s) && s.ValueKind == JsonValueKind.Object && s.TryGetProperty("token", out _))
            _session = s.Clone();
        if (data.TryGetProperty("license", out var l) && l.ValueKind == JsonValueKind.Object) _license = l.Clone();
        if (data.TryGetProperty("product", out var pr) && pr.ValueKind == JsonValueKind.Object)
        {
            _productInfo = pr.Clone();
            if (pr.TryGetProperty("updateAvailable", out var ua) && ua.ValueKind == JsonValueKind.True)
            {
                var latest = pr.TryGetProperty("latest", out var lt) && lt.ValueKind == JsonValueKind.String
                    ? lt.GetString()! : pr.TryGetProperty("version", out var pv) && pv.ValueKind == JsonValueKind.String
                    ? pv.GetString()! : _version;
                Task.Run(() => UpdateAvailable?.Invoke(_version, latest));
            }
        }
        if (data.TryGetProperty("device", out var d) && d.ValueKind == JsonValueKind.Object) _device = d.Clone();
        if (data.TryGetProperty("user", out var u) && u.ValueKind == JsonValueKind.String) _user = u.GetString();
        if (data.TryGetProperty("account", out var a) && a.ValueKind == JsonValueKind.Object) _account = a.Clone();
        if (data.TryGetProperty("subscriptions", out var subs) && subs.ValueKind == JsonValueKind.Array)
            _subscriptions = subs.EnumerateArray().Select(x => x.Clone()).ToList();
        if (data.TryGetProperty("offline", out var off) && off.ValueKind == JsonValueKind.Object)
        {
            if (off.TryGetProperty("assertion", out var asr) && asr.ValueKind == JsonValueKind.String)
            {
                _assertion = asr.GetString();
                _offlineUntil = off.TryGetProperty("notAfter", out var na) && na.ValueKind == JsonValueKind.String
                    ? na.GetString() : null;
            }
        }
    }

    private async Task<JsonElement> SendValidateAsync()
    {
        var hwid = MachineId();
        string? t, k;
        lock (_lock) { t = Token(); k = _storedKey; }
        var payload = new Dictionary<string, object?>
        {
            ["hwid"] = hwid, ["appVersion"] = _version, ["os"] = OsName(),
        };
        if (!string.IsNullOrEmpty(t)) payload["token"] = t;
        else if (!string.IsNullOrEmpty(k)) payload["key"] = k;
        else throw new FrostAuthError("activate before validating", FrostAuthError.Codes.NotActivated);
        return await RequestEnvelopeAsync(HttpMethod.Post, "/api/v1/validate", payload).ConfigureAwait(false);
    }

    private async Task<JsonElement> RequestEnvelopeAsync(
        HttpMethod method, string path, Dictionary<string, object?>? body, string? token = null)
    {
        FrostAuthError? last = null;
        for (var attempt = 0; attempt <= _retries; attempt++)
        {
            if (attempt > 0)
                await Task.Delay(Random.Shared.Next(1, Math.Min(300 * (1 << attempt), 15_000))).ConfigureAwait(false);

            RawResponse raw;
            try { raw = await OneRoundAsync(method, path, body, token).ConfigureAwait(false); }
            catch (FrostAuthError e) when (e.Code == FrostAuthError.Codes.Signature)
            {
                throw;
            }
            catch (FrostAuthError e)
            {
                last = e;
                continue;
            }

            if (raw.Status == 429)
            {
                var wait = 2;
                var delta = raw.RetryAfter;
                if (delta is { } d && d.TotalSeconds is > 0 and <= MaxRetryAfterSeconds) wait = (int)d.TotalSeconds;
                last = new FrostAuthError("Rate limited by the licence server", FrostAuthError.Codes.RateLimited, 429, true)
                { RetryAfterSeconds = wait };
                if (attempt < _retries) { await Task.Delay(wait * 1000).ConfigureAwait(false); continue; }
                throw last;
            }

            JsonElement payload;
            try { payload = string.IsNullOrWhiteSpace(raw.Body) ? default : Json.Deserialize<JsonElement>(raw.Body); }
            catch { payload = default; }

            if (raw.Status >= 500)
            {
                var typed = payload.ValueKind == JsonValueKind.Object
                    && payload.TryGetProperty("response", out var r5)
                    && r5.TryGetProperty("errorCode", out var ec5)
                    && ec5.ValueKind == JsonValueKind.String ? ec5.GetString() : null;
                if (!string.IsNullOrEmpty(typed))
                {
                    var msg = GetString(payload, "response", "message") ?? $"Request failed ({raw.Status})";
                    throw new FrostAuthError(msg, typed!, raw.Status);
                }
                last = new FrostAuthError(
                    GetString(payload, "response", "message") ?? "The licence server is having trouble",
                    FrostAuthError.Codes.ServerError, raw.Status, retryable: true);
                continue;
            }

            var hasError = payload.ValueKind == JsonValueKind.Object
                && payload.TryGetProperty("error", out var errFlag)
                && errFlag.ValueKind is not (JsonValueKind.False or JsonValueKind.Null);
            if (hasError || raw.Status is < 200 or > 299)
            {
                var code = payload.ValueKind == JsonValueKind.Object
                    && payload.TryGetProperty("response", out var r4)
                    && r4.TryGetProperty("errorCode", out var ec4)
                    && ec4.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(ec4.GetString())
                    ? ec4.GetString()! : FrostAuthError.Codes.ServerError;
                var msg = GetString(payload, "response", "message") ?? $"Request failed ({raw.Status})";
                throw new FrostAuthError(msg, code, raw.Status);
            }

            JsonElement data = default;
            if (payload.ValueKind == JsonValueKind.Object
                && payload.TryGetProperty("response", out var resp)
                && resp.ValueKind == JsonValueKind.Object
                && resp.TryGetProperty("data", out var dEl)) data = dEl.Clone();
            lock (_lock) Adopt(data);
            return data;
        }
        throw last ?? new FrostAuthError("Request failed", FrostAuthError.Codes.Network, 0, retryable: true);
    }

    private static string? GetString(JsonElement payload, params string[] path)
    {
        var cur = payload;
        foreach (var seg in path)
        {
            if (cur.ValueKind != JsonValueKind.Object || !cur.TryGetProperty(seg, out cur)) return null;
        }
        return cur.ValueKind == JsonValueKind.String ? cur.GetString() : null;
    }

    private sealed record RawResponse(int Status, string Body, TimeSpan? RetryAfter);

    private async Task<RawResponse> OneRoundAsync(
        HttpMethod method, string path, Dictionary<string, object?>? body, string? token)
    {
        var nonceBytes = RandomNumberGenerator.GetBytes(16);
        var nonce = Convert.ToBase64String(nonceBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        using var req = new HttpRequestMessage(method, path);
        req.Headers.TryAddWithoutValidation("Accept", "application/json");
        req.Headers.TryAddWithoutValidation("User-Agent", $"frostauth-sdk-csharp/{SdkVersion} ({OsName()})");
        req.Headers.TryAddWithoutValidation("X-Frost-Nonce", nonce);
        req.Headers.TryAddWithoutValidation("X-Frost-Timestamp", nowMs.ToString());
        if (body is not null)
        {
            req.Content = new StringContent(Json.Serialize(body), Encoding.UTF8, "application/json");
        }
        if (!string.IsNullOrEmpty(token)) req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");

        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(req).ConfigureAwait(false); }
        catch (TaskCanceledException)
        {
            throw new FrostAuthError($"Request timed out after {_timeout.TotalSeconds:0}s", FrostAuthError.Codes.Timeout, 0, true);
        }
        catch (HttpRequestException)
        {
            throw new FrostAuthError("Could not reach the licence server", FrostAuthError.Codes.Network, 0, true);
        }

        using (resp)
        {
            var responseBody = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            VerifyResponse(resp, responseBody, nonce, method.Method, path);
            return new RawResponse((int)resp.StatusCode, responseBody, resp.Headers.RetryAfter?.Delta);
        }
    }

    private void VerifyResponse(HttpResponseMessage resp, string rawBody, string nonce, string method, string path)
    {
        Dictionary<string, byte[]> currentKeys;
        lock (_lock) currentKeys = _keys;
        if (currentKeys.Count == 0) return;

        var status = (int)resp.StatusCode;
        void Reject(string why) => throw new FrostAuthError($"Refusing an unverified answer from the licence server: {why}", FrostAuthError.Codes.Signature, status);

        var sig = GetHeader(resp.Headers, "x-frost-signature");
        var ts = GetHeader(resp.Headers, "x-frost-timestamp");
        if (string.IsNullOrEmpty(sig) || string.IsNullOrEmpty(ts)) Reject("it was not signed");
        if (GetHeader(resp.Headers, "x-frost-nonce") != nonce) Reject("it answered a different request");
        if (!long.TryParse(ts, out var tsN)) Reject("bad timestamp");
        if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - tsN) > MaxSignatureSkewMs) Reject("it was signed too long ago");
        var keyId = GetHeader(resp.Headers, "x-frost-key-id") ?? "";
        var candidates = currentKeys.Where(kv => string.IsNullOrWhiteSpace(keyId) || kv.Key == keyId).Select(kv => kv.Value).ToList();
        if (candidates.Count == 0) Reject($"it was signed with key \"{keyId}\", which this build does not trust");

        var material = Encoding.UTF8.GetBytes($"{ts}\n{nonce}\n{method.ToUpperInvariant()}\n{path}\n{status}\n{rawBody}");
        byte[] signature;
        try { signature = B64uDecode(sig); }
        catch { Reject("bad signature encoding"); return; }

        foreach (var raw in candidates)
        {
            if (EdVerify(raw, material, signature)) return;
        }
        Reject("the signature did not match");
    }

    private static string? GetHeader(System.Net.Http.Headers.HttpResponseHeaders headers, string name)
    {
        return headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;
    }

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n];

    private async Task<JsonElement> SendRawAsync(HttpMethod method, string path)
    {
        var raw = await OneRoundAsync(method, path, null, null).ConfigureAwait(false);
        try { return Json.Deserialize<JsonElement>(raw.Body); }
        catch { return default; }
    }
}
