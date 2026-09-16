using System.Security.Cryptography;
using System.Text.Json;
using FrostAuth;
using Json = System.Text.Json.JsonSerializer;

var app = FrostAuthClient.Create(new FrostAuthClient.Options
{
    Owner = "0YOUR-OWNER-ID809wkVP",
    Product = "YOUR-PRODUCT-ID",
    Version = "1.0.0",
    // BaseUrl = "https://api.frostauth.cc",
});

try
{
    await app.InitAsync();
}
catch (FrostAuthError e)
{
    Console.WriteLine($"An error occurred: {e.Message}");
    return 1;
}

Console.WriteLine("[1] Login\n[2] Register\n[3] License\n[4] Upgrade");
Console.Write("Select an option: ");
var option = (Console.ReadLine() ?? "").Trim();

string Ask(string prompt)
{
    Console.Write(prompt);
    return (Console.ReadLine() ?? "").Trim();
}

try
{
    switch (option)
    {
        case "1":
            await app.LoginAsync(Ask("Username: "), Ask("Password: "));
            break;
        case "2":
            await app.RegisterAsync(Ask("License: "), Ask("Username: "), Ask("Password: "));
            break;
        case "3":
            await app.ActivateAsync(Ask("License: "));
            break;
        case "4":
            var upUser = Ask("Username: ");
            var upPass = Ask("Password: ");
            var upKey = Ask("License: ");
            await app.UpgradeAsync(upUser, upPass, upKey);
            Console.WriteLine("Upgraded. Sign in to use the new licence.");
            await app.LoginAsync(upUser, upPass);
            break;
        default:
            Console.WriteLine("Invalid option selected.");
            return 0;
    }
}
catch (FrostAuthError e)
{
    Console.WriteLine($"An error occurred: {e.Message}");
    return 1;
}

static JsonElement? Prop(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null ? v : null;

static string Js(JsonElement? e, string dflt = "unknown")
{
    if (e is not { } v) return dflt;
    return v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() ?? dflt,
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null or JsonValueKind.Undefined => dflt,
        _ => v.ToString(),
    };
}

static string Sub(JsonElement snap, string section, string key, string dflt = "unknown") => Prop(snap, section) is { } sec ? Js(Prop(sec, key), dflt) : dflt;

static void ShowUser(JsonElement snap)
{
    static string When(JsonElement? e)
    {
        var s = Loc(e);
        return s == "unknown" ? "—" : s;
    }
    static string Sec(JsonElement? sec, string key) => sec is { } s ? Js(Prop(s, key), "") : "";

    var lic = Prop(snap, "license");
    var account = Prop(snap, "account");
    var device = Prop(snap, "device");
    var product = Prop(snap, "product");

    var who = Js(Prop(snap, "user"), "");
    if (who == "") who = Sec(account, "username");
    if (who == "") who = "unknown";

    var tier = Sec(lic, "tier");
    if (tier == "") tier = "starter";
    var state = Sec(lic, "status");
    if (state == "") state = "unknown";

    JsonElement? expiryEl = lic is { } l0 ? Prop(l0, "expiresAt") : null;
    if (expiryEl is null && Prop(snap, "subscriptions") is { } subsEl && subsEl.ValueKind == JsonValueKind.Array)
        foreach (var s in subsEl.EnumerateArray())
        {
            var e = Prop(s, "expiresAt");
            if (e?.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(e?.GetString())) { expiryEl = e; break; }
        }
    var expiry = expiryEl?.GetString();
    int? daysLeft = null;
    if (!string.IsNullOrWhiteSpace(expiry) && DateTimeOffset.TryParse(expiry, out var edt))
    {
        var diff = edt - DateTimeOffset.Now;
        daysLeft = diff.TotalSeconds <= 0 ? 0 : (int)Math.Ceiling(diff.TotalSeconds / 86400);
    }
    var validLine = string.IsNullOrWhiteSpace(expiry) ? "never" : When(expiryEl) + (daysLeft is { } d ? $" ({d}d left)" : "");

    var prodName = Sec(product, "name");
    if (prodName == "") prodName = "—";
    var prodVer = Sec(product, "version");
    var prodLine = prodName + (prodVer == "" ? "" : $" v{prodVer}");

    var used = lic is { } l2 ? Js(Prop(l2, "devicesUsed"), "—") : "—";
    string devicesLine = used;
    if (lic is { } l3 && Prop(l3, "unlimitedDevices") is { } u && u.ValueKind == JsonValueKind.True)
        devicesLine = $"{used} (unlimited)";
    else if (lic is { } l4 && Prop(l4, "deviceLimit") is { } lim)
        devicesLine = $"{used} / {Js(lim)}";

    var devLine = Sec(device, "id");
    if (devLine == "") devLine = "—";
    var ipLine = Sec(account, "lastIp");
    if (ipLine == "") ipLine = "—";

    Console.WriteLine("");
    Console.WriteLine($"Signed in as {who}");
    Console.WriteLine("----------------------------------------------");
    Console.WriteLine($"  Licence ..... {state} ({tier})");
    Console.WriteLine($"  IP Address .. {ipLine}");
    Console.WriteLine($"  Product ..... {prodLine}");
    Console.WriteLine($"  Devices ..... {devicesLine}");
    Console.WriteLine($"  Valid Until . {validLine}");
    Console.WriteLine($"  Device Id ... {devLine}");
    Console.WriteLine($"  First Seen .. {When(account is { } a4 ? Prop(a4, "createdAt") : null)}");
    Console.WriteLine($"  Last Seen ... {When(account is { } a5 ? Prop(a5, "lastLoginAt") : null)}");
    Console.WriteLine("----------------------------------------------");
}


static string Loc(JsonElement? e)
{
    if (e is not { } v || v.ValueKind != JsonValueKind.String) return "unknown";
    var raw = v.GetString();
    if (string.IsNullOrWhiteSpace(raw) || !DateTimeOffset.TryParse(raw, out var dt)) return "unknown";
    var local = dt.ToLocalTime();
    int h12 = local.Hour % 12; if (h12 == 0) h12 = 12;
    return $"{local.Month}/{local.Day}/{local.Year}, {h12}:{local.Minute:00}:{local.Second:00} {(local.Hour < 12 ? "AM" : "PM")}";
}

var snap = app.Snapshot();

ShowUser(snap);
Console.WriteLine("");

var subList = new List<JsonElement>();
if (Prop(snap, "subscriptions") is { } subsEl && subsEl.ValueKind == JsonValueKind.Array)
    subList.AddRange(subsEl.EnumerateArray());
for (var i = 0; i < subList.Count; i++)
{
    var sub = subList[i];
    var tier = Prop(sub, "tier")?.GetString();
    var name = string.IsNullOrEmpty(tier) ? Prop(sub, "status")?.GetString() : tier;
    var expiry = Prop(sub, "expiresAt") is { } ea ? Loc(ea) : "never";
    Console.WriteLine($"[{i + 1}/{subList.Count}] | Subscription: {name} - Expiry: {expiry}");
}

Console.WriteLine("Created at: " + Sub(snap, "account", "createdAt"));
Console.WriteLine("Last Login: " + Sub(snap, "account", "lastLoginAt"));
var firstExpiry = subList.Select(s => Prop(s, "expiresAt")).FirstOrDefault(e => e is not null);
Console.WriteLine("Expires: " + (firstExpiry is { } fe ? Loc(fe) : "never"));

try
{
    var payload = Json.Serialize(new { content = "Hello from FrostAuth" });
    var res = await app.WebhookAsync("discord", body: payload);
    Console.WriteLine($"\nWebhook test: upstream {Js(Prop(res, "status"))} (ok: {Js(Prop(res, "ok"))})");
}
catch (FrostAuthError e)
{
    Console.WriteLine($"\nWebhook test failed: {e.Code} {e.Message}");
}

var selfHash = "unavailable";
var exe = Environment.ProcessPath;
if (exe is not null && File.Exists(exe))
{
    selfHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(exe))).ToLowerInvariant();
}
Console.WriteLine("\nBuild hash (this file):");
Console.WriteLine($"  {selfHash}");
Console.WriteLine("  Pass it to ActivateAsync/RegisterAsync/LoginAsync (buildHash parameter) when the product requires it.");

Console.WriteLine("\nClosing app in 10 seconds...");
await Task.Delay(10_000);
try { await app.LogoutAsync(); } catch (FrostAuthError) { }
return 0;
