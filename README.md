# FrostAuth-CSHARP-Example 🌟

FrostAuth C# example SDK for https://www.frostauth.cc license key API auth.

This example ships the SDK source directly — the `FrostAuth` project
(`FrostAuthClient.cs` + `FrostAuthError.cs`). Reference it from your app (or
`dotnet pack` it), mirror `ConsoleExample/Program.cs`, and you're integrated.
One NuGet dep: `BouncyCastle.Cryptography` (auto-restored). The
`WinFormsExample` shows the desktop pattern: init on load, license dialog,
heartbeat with offline/invalid handling.

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, .NET SDK (`dotnet --info`), and the
exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
build steps below don't make sense yet, learn some C# first
(docs.microsoft.com/YouTube), then come back.

## Security practices

* Ship releases through an obfuscator/protector (.NET reactor, VMProtect on the
host) and put license checks behind their markers — plain IL decompiles in
seconds (dnSpy). Consider AOT/native publish for the loader.
* Run frequent integrity checks so patched memory kills the session instead of
granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server re-checks the license on
each call — don't add a local `IsValid` boolean that bypasses it.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks stop tampering; the
API stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

* You may not offer this SDK (or a modified copy of it) to third parties as a
hosted or managed service that reproduces any substantial part of FrostAuth.
* You may not move, change, disable, or circumvent the license-key
functionality in the SDK, and you may not remove or obscure any license-key
enforcement it performs.
* You may not remove or obscure any licensing, copyright, or attribution
notices in the SDK files.

Thank you for your compliance — this SDK is a large body of work, and keeping
the notices intact is what keeps it free.

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for C# (this
repo), C++, Python, Go, Rust, Java, and JavaScript. Come ask questions on
Discord: https://www.frostauth.cc/discord

## Requirements

* .NET 8 SDK

## Build

```bash
cd FrostAuth-CSHARP-Example
dotnet build FrostAuth.sln -c Release
dotnet run --project ConsoleExample
dotnet run --project WinFormsExample   # GUI example
```

Or open `FrostAuth.sln` in Visual Studio and F5. Publish + pack:

```bash
dotnet publish ConsoleExample -c Release -o publish-console
dotnet pack FrostAuth -c Release -o nupkg   # FrostAuth.Sdk.1.0.0.nupkg
```

## `FrostAuthClient` instance definition

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`ConsoleExample/Program.cs`](ConsoleExample/Program.cs):

```csharp
var app = FrostAuthClient.Create(new FrostAuthClient.Options {
    Owner = "YOUR-OWNER-ID",    // dashboard → product → owner id
    Product = "YOUR-PRODUCT-ID",// dashboard → product → product id
    Version = "1.0.0",          // must match the version you ship
});
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```csharp
await app.InitAsync();
```

## Display application information

```csharp
var appData = await app.AppDataAsync();
var product = appData.GetProperty("product");
Console.WriteLine("App Version: " + product.GetProperty("version"));
Console.WriteLine("Customer panel: enabled");
```

## Check session validation

Re-checks the license/session with the server. Falls back from a stale session
token to the stored license key once.

```csharp
await app.ValidateAsync(); // throws FrostAuthError when dead — exit, don't continue
```

## Check blacklist status

Whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

```csharp
await app.CheckBlacklistAsync(); // throws on block — exit
```

## Login with username/password

```csharp
var snap = await app.LoginAsync(username, password); // + twofa/buildHash/label overloads
```

## Register with username/password/key

```csharp
var snap = await app.RegisterAsync(key, username, password);
```

## Upgrade user with key

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```csharp
await app.UpgradeAsync(username, password, key);
Console.WriteLine("Upgraded. Sign in to use the new licence.");
var snap = await app.LoginAsync(username, password);
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

```csharp
var snap = await app.ActivateAsync(key); // + buildHash/label overloads
```

## User Data

Everything about the current session lives in the snapshot:

```csharp
var snap = app.Snapshot();
Console.WriteLine("Username: " + snap.GetProperty("user"));
Console.WriteLine("IP: " + snap.GetProperty("account").GetProperty("lastIp"));
Console.WriteLine("Device Id: " + snap.GetProperty("device").GetProperty("id"));
```

## Check subscription of user

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

```csharp
bool pro = snap.GetProperty("subscriptions").EnumerateArray()
    .Any(s => string.Equals(s.GetProperty("tier").GetString(), "pro", StringComparison.OrdinalIgnoreCase));
if (!pro) { Console.WriteLine("This feature needs a Pro subscription."); return; }
```

## Application variables

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```csharp
Console.WriteLine("MOTD: " + await app.VariableAsync("maintenance_message"));
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```csharp
string[] keys = await app.ListVarsAsync();   // every variable key on this user
Console.WriteLine(await app.GetVarAsync("theme")); // one variable's value
await app.SetVarAsync("theme", "dark");      // write it back
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```csharp
await app.LogAsync("client started, integrity check passed");
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```csharp
await app.BanAsync("debugger detected"); // reason shows on next login + dashboard
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```csharp
var res = await app.WebhookAsync("discord", null, "{\"content\":\"Hello from FrostAuth\"}");
Console.WriteLine($"upstream {res.GetProperty("status")} ok: {res.GetProperty("ok")}");
```

## Download file

> Currently disabled server-side (route unmounted). `FileAsync()` throws
> `File downloads are disabled on this server` until file storage ships. The
> snippet below is the integration pattern for when it lands.

```csharp
byte[] blob = await app.FileAsync("loader");
await File.WriteAllBytesAsync("loader.bin", blob);
```

## Changing username

Lets a signed-in user rename themselves (password re-checked server-side).

```csharp
var res = await app.ChangeUsernameAsync(newName, password);
Console.WriteLine("Renamed to " + res.GetProperty("username"));
```

## Heartbeat & offline

`ValidateAsync()` on a timer keeps the session fresh. The SDK caches a signed
offline assertion — when the network drops, `CheckOffline()` verifies it
locally so the app keeps working inside the grace window. Events:
`UpdateAvailable` (current, latest), `Offline` (err, seconds, verified),
`Invalid`, `NeedsActivation`.

```csharp
app.Offline += (err, secs, verified) => Console.WriteLine($"offline: {secs}s verified: {verified}");
app.StartHeartbeat(null); // server cadence until Stop/Close
// ...
var (ok, reason) = app.CheckOffline();
if (!ok) Console.WriteLine("offline: " + reason);
// ...
app.StopHeartbeat();
app.Close();
```

## SDK layout

* `FrostAuth/` — `FrostAuthClient.cs` + `FrostAuthError.cs`. Reference the
project or `dotnet pack` it (`FrostAuth.Sdk.1.0.0.nupkg`).
* `ConsoleExample/` — the interactive demo this README walks through.
* `WinFormsExample/` — desktop pattern: init on load, license dialog, heartbeat.
