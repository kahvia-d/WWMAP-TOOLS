using IMao_WinUI.Core.Updates;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

if (args.FirstOrDefault() == "real-offline")
{
    if (args.Length != 4) throw new ArgumentException("Usage: real-offline <staged-program-directory> <signed-offline.zip> <new-output-directory>");
    await RealOfflineRunner.RunAsync(args[1], args[2], args[3]);
    return;
}

if (args.FirstOrDefault() is "child-activate" or "child-preflight-crash")
{
    var bundled = JsonSerializer.Deserialize<ResourceSnapshot>(File.ReadAllBytes(args[2]), UpdateJson.Options)!;
    var child = new ResourceSnapshotService(args[1], bundled, args[3], (_, _) => { if (args[0] == "child-preflight-crash") Environment.Exit(88); return Task.CompletedTask; });
    await child.InitializeAsync();
    Console.WriteLine(child.Current.SnapshotId);
    return; // Deliberately exit without reporting healthy, to exercise real process identity recovery.
}

var output = Path.GetFullPath(args.FirstOrDefault() ?? "out/resource-updates-tests");
Directory.CreateDirectory(output);
var suiteRoot = Path.Combine(output, "run-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(suiteRoot);
var passed = new List<string>();
var failed = new List<string>();
async Task Test(string name, Func<Task> action)
{
    try { await action(); passed.Add(name); Console.WriteLine("PASS " + name); }
    catch (Exception ex) { failed.Add(name + ": " + ex); Console.WriteLine("FAIL " + name + ": " + ex.Message); }
}
Fixture New() => new(Path.Combine(suiteRoot, Guid.NewGuid().ToString("N")));

await Test("trusted P-256 signature verifies exact signed bytes", async () =>
{
    using var f = New(); await f.Initialize();
    Equal(2L, UpdateSignature.Verify(f.Sign(f.Catalog()), [f.Key], true).Sequence);
});
await Test("test key is rejected by production default", async () =>
{
    using var f = New(); await f.Initialize();
    Throws<InvalidDataException>(() => UpdateSignature.Verify(f.Sign(f.Catalog()), [f.Key]));
});
await Test("unknown key and empty registry fail closed", async () =>
{
    using var f = New(); await f.Initialize();
    Throws<InvalidDataException>(() => UpdateSignature.Verify(f.Sign(f.Catalog()), []));
    Throws<InvalidDataException>(() => UpdateSignature.Verify(f.Sign(f.Catalog()), [f.Key with { KeyId = "other" }], true));
});
await Test("tampering payload or signature is rejected", async () =>
{
    using var f = New(); await f.Initialize();
    var envelope = JsonSerializer.Deserialize<SignedUpdateEnvelope>(f.Sign(f.Catalog()), UpdateJson.Options)!;
    var payload = Convert.FromBase64String(envelope.Payload); payload[^2] ^= 1;
    Throws<InvalidDataException>(() => UpdateSignature.Verify(JsonSerializer.SerializeToUtf8Bytes(envelope with { Payload = Convert.ToBase64String(payload) }), [f.Key], true));
    var signature = Convert.FromBase64String(envelope.Signature); signature[0] ^= 1;
    Throws<InvalidDataException>(() => UpdateSignature.Verify(JsonSerializer.SerializeToUtf8Bytes(envelope with { Signature = Convert.ToBase64String(signature) }), [f.Key], true));
});
await Test("non P-256 signing curve is rejected", async () =>
{
    using var f = New(); await f.Initialize();
    using var other = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    var payload = JsonSerializer.SerializeToUtf8Bytes(f.Catalog(), UpdateJson.Options);
    var envelope = new SignedUpdateEnvelope { KeyId = "p384", Payload = Convert.ToBase64String(payload), Signature = Convert.ToBase64String(other.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
    Throws<InvalidDataException>(() => UpdateSignature.Verify(JsonSerializer.SerializeToUtf8Bytes(envelope), [new TrustedUpdateKey { KeyId = "p384", PublicKey = Convert.ToBase64String(other.ExportSubjectPublicKeyInfo()) }]));
});
await Test("catalog versions, URLs, package kinds and cardinality are enforced", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog(); var release = catalog.Resources[0]; var p = release.Packages[0];
    foreach (var bad in new[] {
        catalog with { SchemaVersion = 2 }, catalog with { Sequence = 0 },
        catalog with { App = catalog.App with { Version = "1.2" } },
        catalog with { App = catalog.App with { Version = " 2026.9.9.1 " } },
        catalog with { App = catalog.App with { Url = "https://github.com/other/repo/releases/tag/1" } },
        catalog with { Resources = [release with { Packages = [] }] },
        catalog with { Resources = [release with { Packages = [p with { Kind = "exe" }] }] },
        catalog with { Resources = [release with { Packages = [p with { Version = "2026.9.9.2 " }] }] },
        catalog with { Resources = [release with { Packages = [p with { Url = "http://github.com/kahvia-d/WWMAP-TOOLS/releases/download/2/data.zip" }] }] },
        catalog with { Resources = [release with { Packages = [p, p] }] },
        catalog with { Resources = [release with { Sequence = 3 }] }
    }) Throws<InvalidDataException>(() => UpdateSignature.ValidateCatalog(bad));
});
await Test("unsafe resource paths and executables are rejected before transfer", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog(); var release = catalog.Resources[0]; var p = release.Packages[0];
    foreach (var path in new[] { "../escape.json", "/absolute.json", "a\\b.json", "C:/bad.json", "a/../b", "a//b", "NUL.json", "com1.json", "a:stream", "trailing. ", "x.exe", "x.dll", "x.ps1", "x.url" })
        Throws<InvalidDataException>(() => UpdateSignature.ValidateCatalog(catalog with { Resources = [release with { Packages = [p with { Files = [p.Files[0] with { Path = path }] }] }] }));
});
await Test("automatic daily checks throttle successes and manual check bypasses throttle", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog());
    False((await f.Updates.CheckAsync(true)).Skipped); Equal(1, f.Network.Requests.Count);
    True((await f.Updates.CheckAsync(true)).Skipped); Equal(1, f.Network.Requests.Count);
    await f.Updates.CheckAsync(false); Equal(2, f.Network.Requests.Count);
    f.Now += TimeSpan.FromHours(25); await f.Updates.CheckAsync(true); Equal(3, f.Network.Requests.Count);
});
await Test("background preference persists and manual checks still work", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog());
    await f.Updates.SetAutoCheckEnabledAsync(false);
    using var second = f.NewUpdates(f.Snapshots); False(second.AutoCheckEnabled); True((await second.CheckAsync(true)).Skipped);
    await second.CheckAsync(); Equal(1, f.Network.Requests.Count);
});
await Test("network error persists as failure and is throttled without claiming latest", async () =>
{
    using var f = New(); await f.Initialize(); f.Network.Fail = true;
    await ThrowsAsync<HttpRequestException>(() => f.Updates.CheckAsync(true));
    True(!string.IsNullOrEmpty(f.Updates.LastError)); True(f.Updates.LastCheckResult is null);
    True((await f.Updates.CheckAsync(true)).Skipped); Equal(1, f.Network.Requests.Count);
});
await Test("corrupt update state disables updater without crashing app or resetting sequence", async () =>
{
    using var f = New(); await f.Initialize(); var path = Path.Combine(f.Root, "update-state.json"); await File.WriteAllTextAsync(path, "{broken");
    using var disabled = f.NewUpdates(f.Snapshots); False(disabled.AutoCheckEnabled); True(disabled.LastError.Contains("防回退")); True(disabled.InitializationError.Contains("防回退"));
    await ThrowsAsync<InvalidDataException>(() => disabled.CheckAsync()); Equal("{broken", File.ReadAllText(path)); Equal(0, f.Network.Requests.Count);
});
await Test("bootstrap failure keeps maps usable while updater fails closed with a readable reason", async () =>
{
    using var f = New(); await f.Initialize();
    using var disabled = new UpdateService(f.Build, [], f.Snapshots, initializationError: "发布密钥清单损坏");
    False(disabled.AutoCheckEnabled); Equal("发布密钥清单损坏", disabled.InitializationError); Equal("发布密钥清单损坏", disabled.LastError);
    await ThrowsAsync<InvalidOperationException>(() => disabled.CheckAsync()); await ThrowsAsync<InvalidOperationException>(() => disabled.InstallAsync());
    await ThrowsAsync<InvalidOperationException>(() => disabled.ImportOfflineAsync("does-not-exist.zip")); Equal("bundled", f.Snapshots.Current.SnapshotId);
});
await Test("network timeout remains an explicit failure rather than user cancellation", async () =>
{
    using var f = New(); await f.Initialize(); f.Network.Timeout = true;
    await ThrowsAsync<TimeoutException>(() => f.Updates.CheckAsync()); True(f.Updates.LastError.Contains("超时")); True(f.Updates.LastCheckResult is null);
});
await Test("highest accepted sequence rejects stale and equivocated catalogs", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog(3)); await f.Updates.CheckAsync();
    f.Publish(f.Catalog(2)); await ThrowsAsync<InvalidDataException>(() => f.Updates.CheckAsync());
    f.Publish(f.Catalog(3) with { App = f.Catalog(3).App with { Notes = "changed without sequence" } });
    await ThrowsAsync<InvalidDataException>(() => f.Updates.CheckAsync());
});
await Test("compatible resource choice is independent of program update", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog(4); var compatible = f.Catalog(2).Resources[0];
    catalog = catalog with { Resources = [catalog.Resources[0] with { MinAppVersion = "2027.1.1.1" }, compatible] };
    f.Publish(catalog); var result = await f.Updates.CheckAsync();
    Equal("snapshot-2", result.Resource!.SnapshotId); True(result.AppUpdate is null); False(result.RequiresAppUpgrade);
});
await Test("incompatible baseline requires program upgrade and prevents install", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog();
    f.Publish(catalog with { Resources = [catalog.Resources[0] with { BaselineId = "new-baseline" }] });
    var result = await f.Updates.CheckAsync(); True(result.RequiresAppUpgrade); True(result.Resource is null);
    await ThrowsAsync<InvalidOperationException>(() => f.Updates.InstallAsync()); Equal(1, f.Network.Requests.Count);
});
await Test("installed snapshots retain signed version bounds in the v2 format", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog();
    catalog = catalog with { Resources = [catalog.Resources[0] with { MaxAppVersion = "2026.9.9.3" }] };
    f.Publish(catalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync();
    Equal(2, next.Current.FormatVersion); Equal("2026.9.9.1", next.Current.MinAppVersion); Equal("2026.9.9.3", next.Current.MaxAppVersion);
});
await Test("older app rejects a pending snapshot requiring newer app before native preflight", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog();
    catalog = catalog with { Resources = [catalog.Resources[0] with { MinAppVersion = "2026.9.9.2" }] };
    var newer = f.NewSnapshots("2026.9.9.2"); await newer.InitializeAsync(); f.Publish(catalog); using var http = new HttpClient(f.Network);
    using var updater = new UpdateService(f.Build with { AppVersion = "2026.9.9.2" }, [f.Key], newer, http, true);
    await updater.CheckAsync(); await updater.InstallAsync(); var preflights = f.PreflightCalls;
    var older = f.NewSnapshots(); await older.InitializeAsync();
    Equal("bundled", older.Current.SnapshotId); False(older.HasPending); Equal(preflights, f.PreflightCalls);
});
await Test("newer app rejects an active snapshot beyond its maximum and keeps user data", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog();
    catalog = catalog with { Resources = [catalog.Resources[0] with { MaxAppVersion = "2026.9.9.1" }] };
    var profile = Path.Combine(f.Root, "../profile-" + Guid.NewGuid().ToString("N") + ".json"); await File.WriteAllTextAsync(profile, "completion-and-route");
    f.Publish(catalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var current = f.NewSnapshots(); await current.InitializeAsync(); await current.ReportHealthyAsync("snapshot-2");
    var upgraded = f.NewSnapshots("2026.9.9.2"); await upgraded.InitializeAsync();
    Equal("bundled", upgraded.Current.SnapshotId); Equal("completion-and-route", File.ReadAllText(profile));
});
await Test("older app restores a compatible successful predecessor of an incompatible active snapshot", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var first = f.NewSnapshots(); await first.InitializeAsync(); await first.ReportHealthyAsync("snapshot-2");
    var newer = f.NewSnapshots("2026.9.9.2"); await newer.InitializeAsync(); using var http = new HttpClient(f.Network);
    using var updater = new UpdateService(f.Build with { AppVersion = "2026.9.9.2" }, [f.Key], newer, http, true);
    var catalog = f.Catalog(3); catalog = catalog with { Resources = [catalog.Resources[0] with { MinAppVersion = "2026.9.9.2" }] };
    f.Publish(catalog); await updater.CheckAsync(); await updater.InstallAsync();
    var active = f.NewSnapshots("2026.9.9.2"); await active.InitializeAsync(); await active.ReportHealthyAsync("snapshot-3");
    var older = f.NewSnapshots(); await older.InitializeAsync(); Equal("snapshot-2", older.Current.SnapshotId); False(older.HasPending);
});
await Test("app upgrade inside the signed closed interval retains the active resource snapshot", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog();
    catalog = catalog with { Resources = [catalog.Resources[0] with { MaxAppVersion = "2026.9.9.3" }] };
    f.Publish(catalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var current = f.NewSnapshots(); await current.InitializeAsync(); await current.ReportHealthyAsync("snapshot-2");
    var upgraded = f.NewSnapshots("2026.9.9.3"); await upgraded.InitializeAsync(); Equal("snapshot-2", upgraded.Current.SnapshotId);
});
await Test("legacy external snapshot fails closed and its signed release can be reimported", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog(); f.Publish(catalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2");
    var legacyPath = Path.Combine(f.Root, "snapshots/snapshot-2.json");
    await File.WriteAllBytesAsync(legacyPath, JsonSerializer.SerializeToUtf8Bytes(next.Current with { FormatVersion = 1, MinAppVersion = "", MaxAppVersion = null }, UpdateJson.Options));
    var activationPath = Path.Combine(f.Root, "activation.json"); var state = JsonNode.Parse(File.ReadAllText(activationPath))!;
    state["activePath"] = legacyPath; await File.WriteAllTextAsync(activationPath, state.ToJsonString());
    var recovered = f.NewSnapshots(); await recovered.InitializeAsync(); Equal("bundled", recovered.Current.SnapshotId);
    using var updater = f.NewUpdates(recovered); await updater.ImportOfflineAsync(f.WriteOffline(catalog));
    var reimported = f.NewSnapshots(); await reimported.InitializeAsync(); Equal("snapshot-2", reimported.Current.SnapshotId); Equal(2, reimported.Current.FormatVersion);
    True(File.Exists(legacyPath));
});
await Test("missing malformed and inverted v2 bounds fail closed before resource preflight", async () =>
{
    foreach (var bounds in new[] { ("", (string?)null), ("1.2", (string?)null), ("2026.9.9.1", ""), ("2026.9.9.3", "2026.9.9.1") })
    {
        using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
        var pendingPath = Path.Combine(f.Root, "snapshots/v2/snapshot-2.json");
        var pending = JsonSerializer.Deserialize<ResourceSnapshot>(File.ReadAllBytes(pendingPath), UpdateJson.Options)!;
        await File.WriteAllBytesAsync(pendingPath, JsonSerializer.SerializeToUtf8Bytes(pending with { MinAppVersion = bounds.Item1, MaxAppVersion = bounds.Item2 }, UpdateJson.Options));
        var preflights = f.PreflightCalls; var restarted = f.NewSnapshots(); await restarted.InitializeAsync();
        Equal("bundled", restarted.Current.SnapshotId); False(restarted.HasPending); Equal(preflights, f.PreflightCalls);
    }
});
await Test("online install remains pending and old process keeps its snapshot", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog());
    await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    True(f.Snapshots.HasPending); Equal("bundled", f.Snapshots.Current.SnapshotId); Equal(1, f.PreflightCalls);
    True(!File.Exists(Path.Combine(f.Root, "packages/map-data/2026.9.9.2/.package.json")));
    True(File.Exists(Path.Combine(f.Root, "packages/map-data/2026.9.9.2.receipt.json")));
});
await Test("healthy startup commits only matching CoreHost snapshot and enables rollback", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); Equal("snapshot-2", next.Current.SnapshotId);
    await ThrowsAsync<InvalidDataException>(() => next.ReportHealthyAsync("wrong")); True(next.HasPending);
    await next.ReportHealthyAsync("snapshot-2"); False(next.HasPending); True(next.CanRollback);
    var restarted = f.NewSnapshots(); await restarted.InitializeAsync(); Equal("snapshot-2", restarted.Current.SnapshotId);
});
await Test("simultaneous startup uses stable snapshot while first candidate is unconfirmed", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var first = f.NewSnapshots(); await first.InitializeAsync(); Equal("snapshot-2", first.Current.SnapshotId);
    var second = f.NewSnapshots(); await second.InitializeAsync(); Equal("bundled", second.Current.SnapshotId);
    await second.ReportHealthyAsync("bundled"); True(second.HasPending);
    await first.ReportHealthyAsync("snapshot-2");
});
await Test("real child exit before healthy confirmation restores stable snapshot", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var bundledPath = Path.Combine(f.Root, "bundled-for-child.json"); await File.WriteAllBytesAsync(bundledPath, JsonSerializer.SerializeToUtf8Bytes(f.Bundled, UpdateJson.Options));
    var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(typeof(Fixture).Assembly.Location);
    info.ArgumentList.Add("child-activate"); info.ArgumentList.Add(f.Root); info.ArgumentList.Add(bundledPath); info.ArgumentList.Add(f.Build.AppVersion);
    using var process = Process.Start(info)!; await process.WaitForExitAsync(); Equal(0, process.ExitCode); True((await process.StandardOutput.ReadToEndAsync()).Contains("snapshot-2"));
    var next = f.NewSnapshots(); await next.InitializeAsync(); Equal("bundled", next.Current.SnapshotId); False(next.HasPending);
});
await Test("real process crash during candidate preflight does not create restart loop", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var bundledPath = Path.Combine(f.Root, "bundled-for-child.json"); await File.WriteAllBytesAsync(bundledPath, JsonSerializer.SerializeToUtf8Bytes(f.Bundled, UpdateJson.Options));
    var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(typeof(Fixture).Assembly.Location);
    info.ArgumentList.Add("child-preflight-crash"); info.ArgumentList.Add(f.Root); info.ArgumentList.Add(bundledPath); info.ArgumentList.Add(f.Build.AppVersion);
    using var process = Process.Start(info)!; await process.WaitForExitAsync(); Equal(88, process.ExitCode);
    var next = f.NewSnapshots(); await next.InitializeAsync(); Equal("bundled", next.Current.SnapshotId); False(next.HasPending);
});
await Test("candidate preflight failure does not activate or loop", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); f.PreflightFails = true;
    await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync()); False(f.Snapshots.HasPending); Equal("bundled", f.Snapshots.Current.SnapshotId);
});
await Test("corrupted pending payload rolls back on restart", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    await File.WriteAllTextAsync(Path.Combine(f.Root, "packages/map-data/2026.9.9.2/markers.json"), "corrupted");
    var next = f.NewSnapshots(); await next.InitializeAsync(); Equal("bundled", next.Current.SnapshotId); False(next.HasPending);
});
await Test("rollback queues entire prior snapshot and requires restart", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2"); await next.QueueRollbackAsync();
    Equal("snapshot-2", next.Current.SnapshotId); True(next.HasPending);
    var rollback = f.NewSnapshots(); await rollback.InitializeAsync(); Equal("bundled", rollback.Current.SnapshotId); await rollback.ReportHealthyAsync("bundled");
});
await Test("updates and rollback preserve arbitrary local user data byte-for-byte", async () =>
{
    using var f = New(); await f.Initialize(); var userdata = Path.Combine(f.Root, "../user-data"); Directory.CreateDirectory(userdata);
    var original = Encoding.UTF8.GetBytes("completed: 1001; route: 1002,1001; filter: all; token: unused"); var path = Path.Combine(userdata, "profile.json"); await File.WriteAllBytesAsync(path, original);
    f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync(); var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2"); await next.QueueRollbackAsync();
    True(File.ReadAllBytes(path).SequenceEqual(original));
});
await Test("complete offline package installs with zero network calls", async () =>
{
    using var f = New(); await f.Initialize(); f.Network.Fail = true; var offline = f.WriteOffline(f.Catalog());
    await f.Updates.ImportOfflineAsync(offline); True(f.Snapshots.HasPending); Equal(0, f.Network.Requests.Count);
});
await Test("offline incomplete package and extra entries fail atomically", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog();
    var missing = f.WriteOffline(catalog, omitPackage: true); await ThrowsAsync<InvalidDataException>(() => f.Updates.ImportOfflineAsync(missing));
    var extra = f.WriteOffline(catalog, extra: "extras/readme.txt"); await ThrowsAsync<InvalidDataException>(() => f.Updates.ImportOfflineAsync(extra));
    False(f.Snapshots.HasPending); Equal(0, f.Network.Requests.Count);
});
await Test("offline downgrade catalog is rejected after newer online catalog", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog(3)); await f.Updates.CheckAsync();
    await ThrowsAsync<InvalidDataException>(() => f.Updates.ImportOfflineAsync(f.WriteOffline(f.Catalog(2)))); False(f.Snapshots.HasPending);
});
await Test("insufficient disk fails before package download", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); f.FreeBytes = 10; await f.Updates.CheckAsync();
    await ThrowsAsync<IOException>(() => f.Updates.InstallAsync()); False(f.Snapshots.HasPending); Equal(1, f.Network.Requests.Count);
});
await Test("package corruption and declared length mismatch are rejected", async () =>
{
    using var f = New(); await f.Initialize(); var catalog = f.Catalog(); f.Publish(catalog); await f.Updates.CheckAsync();
    var bytes = f.Network.Routes[catalog.Resources[0].Packages[0].Url].ToArray(); bytes[^1] ^= 1; f.Network.Routes[catalog.Resources[0].Packages[0].Url] = bytes;
    await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync()); False(f.Snapshots.HasPending);
    f.Network.Routes[catalog.Resources[0].Packages[0].Url] = [1, 2, 3]; await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync());
});
await Test("cancellation during package streaming never sets pending", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync();
    using var cancel = new CancellationTokenSource();
    var progress = new InlineProgress(p => { if (p.Stage == "下载资源") cancel.Cancel(); });
    await ThrowsAsync<OperationCanceledException>(() => f.Updates.InstallAsync(progress, cancel.Token)); False(f.Snapshots.HasPending);
    Equal("bundled", f.Snapshots.Current.SnapshotId);
});
await Test("cancelled install is retryable without changing signed versions", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync();
    using var cancel = new CancellationTokenSource(); cancel.Cancel();
    await ThrowsAsync<OperationCanceledException>(() => f.Updates.InstallAsync(ct: cancel.Token));
    await f.Updates.InstallAsync(); True(f.Snapshots.HasPending);
});
await Test("ZIP traversal duplicate missing extra and symlink payload entries are rejected", async () =>
{
    using var f = New(); await f.Initialize();
    foreach (var mode in new[] { "traversal", "duplicate", "missing", "extra", "symlink" })
    {
        var package = f.MakePackage("map-data", "map-data", "2026.9.9.2", "safe", mode);
        var catalog = f.Catalog() with { Resources = [f.Catalog().Resources[0] with { Packages = [package] }] };
        // Each malformed fixture is assigned its own new signed catalog sequence.
        var index = Array.IndexOf(new[] { "traversal", "duplicate", "missing", "extra", "symlink" }, mode) + 2;
        catalog = catalog with { Sequence = index, Resources = [catalog.Resources[0] with { Sequence = index, SnapshotId = "snapshot-" + index }] };
        f.Publish(catalog); await f.Updates.CheckAsync(); await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync());
        False(f.Snapshots.HasPending);
    }
    False(File.Exists(Path.Combine(f.Root, "escape.json")));
});
await Test("same package id and version cannot acquire different content", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2"); using var updater = f.NewUpdates(next);
    var package = f.MakePackage("map-data", "map-data", "2026.9.9.2", "changed");
    var catalog = f.Catalog(3) with { Resources = [f.Catalog(3).Resources[0] with { Packages = [package] }] };
    f.Publish(catalog); await updater.CheckAsync(); await ThrowsAsync<InvalidDataException>(() => updater.InstallAsync()); False(next.HasPending);
});
await Test("complete payload with interrupted receipt write recovers after signed verification", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    File.Delete(Path.Combine(f.Root, "packages/map-data/2026.9.9.2.receipt.json"));
    var requests = f.Network.Requests.Count; await f.Updates.InstallAsync(); Equal(requests, f.Network.Requests.Count);
    True(File.Exists(Path.Combine(f.Root, "packages/map-data/2026.9.9.2.receipt.json")));
});
await Test("incomplete orphan payload cannot be blessed by receipt recovery", async () =>
{
    using var f = New(); await f.Initialize(); f.Publish(f.Catalog()); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    File.Delete(Path.Combine(f.Root, "packages/map-data/2026.9.9.2.receipt.json")); File.Delete(Path.Combine(f.Root, "packages/map-data/2026.9.9.2/markers.json"));
    await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync()); False(File.Exists(Path.Combine(f.Root, "packages/map-data/2026.9.9.2.receipt.json")));
});
await Test("only changed feature package is downloaded on subsequent update", async () =>
{
    using var f = New(); await f.Initialize(); var first = f.Catalog(); var data = first.Resources[0].Packages[0]; var tile1 = f.MakePackage("world-tile", "tile", "2026.9.9.2", "tile-v2");
    first = first with { Resources = [first.Resources[0] with { Packages = [data, tile1] }] }; f.Publish(first); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2"); using var updater = f.NewUpdates(next);
    var second = f.Catalog(3); var tile2 = f.MakePackage("world-tile", "tile", "2026.9.9.3", "tile-v3"); second = second with { Resources = [second.Resources[0] with { Packages = [data, tile2] }] }; f.Publish(second);
    f.Network.Requests.Clear(); var check = await updater.CheckAsync(); True(check.AppUpdate is null); await updater.InstallAsync();
    Equal(2, f.Network.Requests.Count); True(f.Network.Requests.Contains(tile2.Url)); False(f.Network.Requests.Contains(data.Url));
});
await Test("only changed map-data package is downloaded while feature stays shared", async () =>
{
    using var f = New(); await f.Initialize(); var first = f.Catalog(); var tile = f.MakePackage("world-tile", "tile", "2026.9.9.2", "tile-v2");
    first = first with { Resources = [first.Resources[0] with { Packages = [first.Resources[0].Packages[0], tile] }] }; f.Publish(first); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2"); using var updater = f.NewUpdates(next);
    var second = f.Catalog(3); second = second with { Resources = [second.Resources[0] with { Packages = [second.Resources[0].Packages[0], tile] }] }; f.Publish(second);
    f.Network.Requests.Clear(); await updater.CheckAsync(); await updater.InstallAsync(); Equal(2, f.Network.Requests.Count); False(f.Network.Requests.Contains(tile.Url));
});
await Test("unchanged bundled package is verified and reused without download or copy", async () =>
{
    using var f = New(); var data = f.MakePackage("map-data", "map-data", "2026.9.9.1", "bundled-data");
    var bundleDirectory = Path.Combine(f.Root, "baseline/data"); Directory.CreateDirectory(bundleDirectory); await File.WriteAllTextAsync(Path.Combine(bundleDirectory, "markers.json"), "bundled-data");
    f.Bundled = f.Bundled with { MapDataRoot = bundleDirectory, Packages = [new SnapshotPackage { Id = data.Id, Version = data.Version, Kind = data.Kind, Directory = bundleDirectory }] };
    await f.Initialize(); var catalog = f.Catalog(); var tile = f.MakePackage("new-tile", "tile", "2026.9.9.2", "tile-new");
    catalog = catalog with { Resources = [catalog.Resources[0] with { Packages = [data, tile] }] }; f.Publish(catalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    Equal(2, f.Network.Requests.Count); False(f.Network.Requests.Contains(data.Url)); False(Directory.Exists(Path.Combine(f.Root, "packages/map-data")));
    var next = f.NewSnapshots(); await next.InitializeAsync(); Equal(bundleDirectory, next.Current.MapDataRoot); await next.ReportHealthyAsync("snapshot-2");
});
await Test("file archives download only the changed file and reuse an older package version", async () =>
{
    using var f = New(); await f.Initialize();
    var first = f.MakeMultiFilePackage("lahai-tile", "tile", "2026.9.9.2", ("manifest.json", "old"), ("features.imf", "large-stable"), ("features.yml", "large-stable-yml"));
    var firstCatalog = f.Catalog() with { Resources = [f.Catalog().Resources[0] with { Packages = [f.Catalog().Resources[0].Packages[0], first] }] };
    f.Publish(firstCatalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var current = f.NewSnapshots(); await current.InitializeAsync(); await current.ReportHealthyAsync("snapshot-2"); using var updater = f.NewUpdates(current);
    var changed = f.MakeMultiFilePackage("lahai-tile", "tile", "2026.9.9.3", ("manifest.json", "new"), ("features.imf", "large-stable"), ("features.yml", "large-stable-yml"));
    var next = f.Catalog(3) with { Resources = [f.Catalog(3).Resources[0] with { Packages = [firstCatalog.Resources[0].Packages[0], changed] }] };
    f.Publish(next); f.Network.Requests.Clear(); await updater.CheckAsync(); await updater.InstallAsync();
    Equal(2, f.Network.Requests.Count); True(f.Network.Requests.Contains(changed.FileArchives!.Single(a => a.Path == "manifest.json").Url)); False(f.Network.Requests.Contains(changed.Url));
    False(f.Network.Requests.Contains(changed.FileArchives!.Single(a => a.Path == "features.imf").Url));
});
await Test("file archive rejects an unexpected path without staging", async () =>
{
    using var f = New(); await f.Initialize(); var package = f.MakePackage("map-data", "map-data", "2026.9.9.2", "changed");
    var archive = package.FileArchives!.Single(); f.Network.Routes[archive.Url] = f.ZipForTest(("wrong.json", Encoding.UTF8.GetBytes("changed"), 0));
    var catalog = f.Catalog() with { Resources = [f.Catalog().Resources[0] with { Packages = [package] }] }; f.Publish(catalog); await f.Updates.CheckAsync();
    await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync()); False(f.Snapshots.HasPending);
});
await Test("same-baseline moved app rebinds proven bundled payload and native snapshot paths", async () =>
{
    using var f = New(); var data = f.MakePackage("map-data", "map-data", "2026.9.9.1", "bundled-data");
    var directory = Path.Combine(f.Root, "baseline/data"); Directory.CreateDirectory(directory); await File.WriteAllTextAsync(Path.Combine(directory, "markers.json"), "bundled-data");
    f.Bundled = f.Bundled with { MapDataRoot = directory, Packages = [new SnapshotPackage { Id = data.Id, Version = data.Version, Kind = data.Kind, Directory = directory }] };
    await f.Initialize(); var catalog = f.Catalog() with { Resources = [f.Catalog().Resources[0] with { Packages = [data] }] }; f.Publish(catalog); await f.Updates.CheckAsync(); await f.Updates.InstallAsync();
    var next = f.NewSnapshots(); await next.InitializeAsync(); await next.ReportHealthyAsync("snapshot-2");
    var movedRoot = Path.Combine(f.Root, "moved-baseline"); var movedData = Path.Combine(movedRoot, "data"); Directory.CreateDirectory(movedData); await File.WriteAllTextAsync(Path.Combine(movedData, "markers.json"), "bundled-data");
    f.Bundled = f.Bundled with { BaselineRoot = movedRoot, MapDataRoot = movedData, Packages = [f.Bundled.Packages[0] with { Directory = movedData }] };
    var moved = f.NewSnapshots(); await moved.InitializeAsync(); Equal("snapshot-2", moved.Current.SnapshotId); Equal(movedData, moved.Current.MapDataRoot);
    var runtime = JsonSerializer.Deserialize<ResourceSnapshot>(File.ReadAllBytes(moved.CurrentPath), UpdateJson.Options)!;
    Equal(movedRoot, runtime.BaselineRoot); Equal(movedData, runtime.MapDataRoot);
});
await Test("unexpected files in bundled resources fail reuse and retain current snapshot", async () =>
{
    using var f = New(); var data = f.MakePackage("map-data", "map-data", "2026.9.9.1", "bundled-data"); var directory = Path.Combine(f.Root, "baseline/data"); Directory.CreateDirectory(directory);
    await File.WriteAllTextAsync(Path.Combine(directory, "markers.json"), "bundled-data"); await File.WriteAllTextAsync(Path.Combine(directory, "unexpected.json"), "extra");
    f.Bundled = f.Bundled with { MapDataRoot = directory, Packages = [new SnapshotPackage { Id = data.Id, Version = data.Version, Kind = data.Kind, Directory = directory }] };
    await f.Initialize(); var catalog = f.Catalog() with { Resources = [f.Catalog().Resources[0] with { Packages = [data] }] }; f.Publish(catalog); await f.Updates.CheckAsync();
    await ThrowsAsync<InvalidDataException>(() => f.Updates.InstallAsync()); False(f.Snapshots.HasPending);
});
await Test("offline reused bundled payload still requires exact archive hash verification", async () =>
{
    using var f = New(); var data = f.MakePackage("map-data", "map-data", "2026.9.9.1", "bundled-data"); var directory = Path.Combine(f.Root, "baseline/data"); Directory.CreateDirectory(directory);
    await File.WriteAllTextAsync(Path.Combine(directory, "markers.json"), "bundled-data");
    f.Bundled = f.Bundled with { MapDataRoot = directory, Packages = [new SnapshotPackage { Id = data.Id, Version = data.Version, Kind = data.Kind, Directory = directory }] };
    await f.Initialize(); var catalog = f.Catalog() with { Resources = [f.Catalog().Resources[0] with { Packages = [data] }] };
    var corrupted = f.Network.Routes[data.Url].ToArray(); corrupted[^1] ^= 1; f.Network.Routes[data.Url] = corrupted;
    await ThrowsAsync<InvalidDataException>(() => f.Updates.ImportOfflineAsync(f.WriteOffline(catalog)));
    False(f.Snapshots.HasPending); Equal(0, f.Network.Requests.Count); Equal("bundled-data", File.ReadAllText(Path.Combine(directory, "markers.json")));
});
await Test("cross-process lock wait honors cancellation", async () =>
{
    using var f = New(); await f.Initialize(); using var held = new FileStream(Path.Combine(f.Root, ".update.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
    await ThrowsAsync<OperationCanceledException>(() => f.Updates.CheckAsync(ct: cancellation.Token));
});
await Test("untrusted redirects are rejected before following them", async () =>
{
    using var f = New(); await f.Initialize(); f.Network.Redirect = new Uri("https://example.com/steal");
    await ThrowsAsync<InvalidDataException>(() => f.Updates.CheckAsync()); Equal(1, f.Network.Requests.Count);
});
await Test("manifest response size limit rejects unbounded input", async () =>
{
    using var f = New(); await f.Initialize(); f.Network.Routes[UpdateService.StableUri.AbsoluteUri] = new byte[UpdateSignature.MaxManifestBytes + 1];
    await ThrowsAsync<InvalidDataException>(() => f.Updates.CheckAsync());
});
await Test("atomic state replace recovers from a temporary Windows reader without removing old state", async () =>
{
    using var f = New(); var path = Path.Combine(f.Root, "held-state.json"); await File.WriteAllTextAsync(path, "old-state");
    var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    try
    {
        var write = UpdateStorage.WriteAsync(path, new { value = "new-state" }, CancellationToken.None);
        await Task.Delay(150); Equal("old-state", File.ReadAllText(path)); False(write.IsCompleted);
        held.Dispose(); await write; True(File.ReadAllText(path).Contains("new-state"));
    }
    finally { held.Dispose(); }
});
await Test("persistent Windows state reader preserves old bytes and returns the original IO failure", async () =>
{
    using var f = New(); var path = Path.Combine(f.Root, "held-state.json"); await File.WriteAllTextAsync(path, "old-state");
    using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    try { await UpdateStorage.WriteAsync(path, new { value = "new-state" }, CancellationToken.None); throw new Exception("Expected locked state replacement failure."); }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { True((ex.HResult & 0xFFFF) is 5 or 32 or 33); }
    Equal("old-state", File.ReadAllText(path));
});
await Test("state replacement retry remains cancellable while retaining old state", async () =>
{
    using var f = New(); var path = Path.Combine(f.Root, "held-state.json"); await File.WriteAllTextAsync(path, "old-state");
    using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read); using var cancel = new CancellationTokenSource(150);
    await ThrowsAsync<OperationCanceledException>(() => UpdateStorage.WriteAsync(path, new { value = "new-state" }, cancel.Token)); Equal("old-state", File.ReadAllText(path));
});
await Test("package directory promotion recovers after a temporary Windows reader releases it", async () =>
{
    using var f = New(); var source = Path.Combine(f.Root, "unpacked"); var target = Path.Combine(f.Root, "installed"); Directory.CreateDirectory(source);
    var path = Path.Combine(source, "data.json"); await File.WriteAllTextAsync(path, "signed-content");
    var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    try
    {
        var move = UpdateStorage.MoveDirectoryAsync(source, target, CancellationToken.None);
        await Task.Delay(150); True(Directory.Exists(source)); False(Directory.Exists(target)); False(move.IsCompleted);
        held.Dispose(); await move; Equal("signed-content", File.ReadAllText(Path.Combine(target, "data.json"))); False(Directory.Exists(source));
    }
    finally { held.Dispose(); }
});
await Test("persistent package directory reader leaves source intact and creates no installed target", async () =>
{
    using var f = New(); var source = Path.Combine(f.Root, "unpacked"); var target = Path.Combine(f.Root, "installed"); Directory.CreateDirectory(source);
    var path = Path.Combine(source, "data.json"); await File.WriteAllTextAsync(path, "signed-content"); using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    try { await UpdateStorage.MoveDirectoryAsync(source, target, CancellationToken.None); throw new Exception("Expected locked directory promotion failure."); }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { True((ex.HResult & 0xFFFF) is 5 or 32 or 33); }
    Equal("signed-content", File.ReadAllText(path)); False(Directory.Exists(target));
});
await Test("package directory promotion retry respects cancellation without deleting payload", async () =>
{
    using var f = New(); var source = Path.Combine(f.Root, "unpacked"); var target = Path.Combine(f.Root, "installed"); Directory.CreateDirectory(source);
    var path = Path.Combine(source, "data.json"); await File.WriteAllTextAsync(path, "signed-content"); using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
    using var cancel = new CancellationTokenSource(150);
    await ThrowsAsync<OperationCanceledException>(() => UpdateStorage.MoveDirectoryAsync(source, target, cancel.Token)); Equal("signed-content", File.ReadAllText(path)); False(Directory.Exists(target));
});

await File.WriteAllTextAsync(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new { passed = passed.Count, failed = failed.Count, checks = passed, failures = failed, evidenceDirectory = suiteRoot }, UpdateJson.Options));
Console.WriteLine($"Resource update checks: {passed.Count} passed, {failed.Count} failed. Evidence: {suiteRoot}");
if (failed.Count > 0) Environment.ExitCode = 1;

static void True(bool value) { if (!value) throw new Exception("Expected true."); }
static void False(bool value) => True(!value);
static void Equal<T>(T expected, T actual) { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"Expected {expected}; actual {actual}."); }
static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
static async Task ThrowsAsync<T>(Func<Task> action) where T : Exception { try { await action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }

sealed class InlineProgress(Action<UpdateProgress> report) : IProgress<UpdateProgress>
{
    public void Report(UpdateProgress value) => report(value);
}

sealed class FakeNetwork : HttpMessageHandler
{
    public Dictionary<string, byte[]> Routes { get; } = new();
    public List<string> Requests { get; } = new();
    public bool Fail { get; set; }
    public bool Timeout { get; set; }
    public Uri? Redirect { get; set; }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); var url = request.RequestUri!.AbsoluteUri; Requests.Add(url);
        if (Fail) throw new HttpRequestException("Injected network failure.");
        if (Timeout) throw new TaskCanceledException("Injected transport timeout.");
        if (Redirect is not null) { var redirect = new HttpResponseMessage(HttpStatusCode.Redirect) { RequestMessage = request }; redirect.Headers.Location = Redirect; return Task.FromResult(redirect); }
        if (!Routes.TryGetValue(url, out var bytes)) throw new HttpRequestException("Unknown test URL: " + url);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request, Content = new ByteArrayContent(bytes) });
    }
}

sealed class Fixture : IDisposable
{
    private readonly ECDsa _signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly HttpClient _http;
    public string Root { get; }
    public BuildInfo Build { get; } = new() { AppVersion = "2026.9.9.1", BaselineId = "test-baseline" };
    public ResourceSnapshot Bundled { get; set; }
    public TrustedUpdateKey Key { get; }
    public FakeNetwork Network { get; } = new();
    public ResourceSnapshotService Snapshots { get; private set; } = null!;
    public UpdateService Updates { get; private set; } = null!;
    public DateTimeOffset Now { get; set; } = new(2026, 9, 9, 0, 0, 0, TimeSpan.Zero);
    public long FreeBytes { get; set; } = long.MaxValue;
    public bool PreflightFails { get; set; }
    public int PreflightCalls { get; private set; }
    public Fixture(string root)
    {
        Root = root; Directory.CreateDirectory(root); _http = new HttpClient(Network);
        Key = new TrustedUpdateKey { KeyId = "test-only", TestOnly = true, PublicKey = Convert.ToBase64String(_signer.ExportSubjectPublicKeyInfo()) };
        Bundled = new ResourceSnapshot { SnapshotId = "bundled", BaselineId = Build.BaselineId, BaselineRoot = Path.Combine(root, "baseline"), MapDataRoot = Path.Combine(root, "baseline/data"), Bundled = true };
    }
    public async Task Initialize() { Snapshots = NewSnapshots(); await Snapshots.InitializeAsync(); Updates = NewUpdates(Snapshots); }
    public ResourceSnapshotService NewSnapshots(string? appVersion = null) => new(Root, Bundled, appVersion ?? Build.AppVersion, (_, ct) => { ct.ThrowIfCancellationRequested(); PreflightCalls++; if (PreflightFails) throw new InvalidDataException("Injected preflight failure."); return Task.CompletedTask; });
    public UpdateService NewUpdates(ResourceSnapshotService snapshots) => new(Build, [Key], snapshots, _http, true, () => Now, () => FreeBytes);
    public UpdateCatalog Catalog(long sequence = 2)
    {
        var package = MakePackage("map-data", "map-data", "2026.9.9." + sequence, "{\"marker\":" + sequence + "}");
        return new UpdateCatalog
        {
            Sequence = sequence, App = new ProgramRelease { Version = Build.AppVersion, Url = "https://github.com/kahvia-d/WWMAP-TOOLS/releases/tag/2026.9.9.1" },
            Resources = [new ResourceRelease { SnapshotId = "snapshot-" + sequence, Sequence = sequence, BaselineId = Build.BaselineId, MinAppVersion = Build.AppVersion, Packages = [package] }]
        };
    }
    public ResourcePackage MakePackage(string id, string kind, string version, string text, string? malformed = null)
    {
        var bytes = Encoding.UTF8.GetBytes(text); var name = kind == "map-data" ? "markers.json" : "features.bin";
        var entries = new List<(string, byte[], int)> { (name, bytes, malformed == "symlink" ? 0xA000 << 16 : 0) };
        if (malformed == "traversal") entries.Add(("../escape.json", [1], 0));
        if (malformed == "duplicate") entries.Add((name.ToUpperInvariant(), bytes, 0));
        if (malformed == "missing") entries.Clear();
        if (malformed == "extra") entries.Add(("extra.json", [1], 0));
        var zip = Zip(entries); var url = $"https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/{version}/{id}.zip"; Network.Routes[url] = zip;
        var file = new ResourceFile { Path = name, Size = bytes.Length, Sha256 = Hash(bytes) };
        if (malformed is not null) return new ResourcePackage { Id = id, Kind = kind, Version = version, Url = url, Size = zip.Length, Sha256 = Hash(zip), Files = [file] };
        var package = MakePackageFromEntries(id, kind, version, entries, [file], zip, url);
        return package;
    }
    public ResourcePackage MakeMultiFilePackage(string id, string kind, string version, params (string name, string text)[] files)
    {
        var entries = files.Select(x => (x.name, Encoding.UTF8.GetBytes(x.text), 0)).ToList(); var zip = Zip(entries); var url = $"https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/{version}/{id}.zip";
        return MakePackageFromEntries(id, kind, version, entries, entries.Select(x => new ResourceFile { Path = x.name, Size = x.Item2.Length, Sha256 = Hash(x.Item2) }).ToList(), zip, url);
    }
    private ResourcePackage MakePackageFromEntries(string id, string kind, string version, List<(string, byte[], int)> entries, List<ResourceFile> files, byte[] zip, string url)
    {
        Network.Routes[url] = zip;
        var archives = new List<ResourceFileArchive>();
        foreach (var file in files)
        {
            var item = entries.Single(e => e.Item1 == file.Path); var bytes = Zip([(file.Path, item.Item2, 0)]); var fileUrl = $"https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/{version}/file-{file.Sha256.ToLowerInvariant()}.zip";
            Network.Routes[fileUrl] = bytes; archives.Add(new() { Path = file.Path, Url = fileUrl, Size = bytes.Length, Sha256 = Hash(bytes) });
        }
        return new ResourcePackage { Id = id, Kind = kind, Version = version, Url = url, Size = zip.Length, Sha256 = Hash(zip), Files = files, FileArchives = archives };
    }
    public byte[] ZipForTest(params (string name, byte[] bytes, int attributes)[] entries) => Zip(entries);
    public byte[] Sign(UpdateCatalog catalog)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(catalog, UpdateJson.Options);
        return JsonSerializer.SerializeToUtf8Bytes(new SignedUpdateEnvelope { KeyId = Key.KeyId, Payload = Convert.ToBase64String(payload), Signature = Convert.ToBase64String(_signer.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) }, UpdateJson.Options);
    }
    public void Publish(UpdateCatalog catalog) => Network.Routes[UpdateService.StableUri.AbsoluteUri] = Sign(catalog);
    public string WriteOffline(UpdateCatalog catalog, bool omitPackage = false, string? extra = null)
    {
        var entries = new List<(string, byte[], int)> { ("update.json", Sign(catalog), 0) };
        if (!omitPackage) foreach (var package in catalog.Resources[0].Packages) entries.Add(("packages/" + package.Id + "-" + package.Version + ".zip", Network.Routes[package.Url], 0));
        if (extra is not null) entries.Add((extra, [1, 2, 3], 0));
        var path = Path.Combine(Root, "offline-" + Guid.NewGuid().ToString("N") + ".zip"); File.WriteAllBytes(path, Zip(entries)); return path;
    }
    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static byte[] Zip(IEnumerable<(string name, byte[] bytes, int attributes)> entries)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, true)) foreach (var entry in entries)
        {
            var item = zip.CreateEntry(entry.name, CompressionLevel.NoCompression); item.ExternalAttributes = entry.attributes; item.LastWriteTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero); using var target = item.Open(); target.Write(entry.bytes);
        }
        return output.ToArray();
    }
    public void Dispose() { Updates?.Dispose(); _http.Dispose(); _signer.Dispose(); }
}
