using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using IMao_WinUI.Core.Updates;

return await Publisher.Run(args);

static class Publisher
{
    static readonly JsonSerializerOptions Json = UpdateJson.Options;
    static readonly DateTimeOffset ZipEpoch = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
    static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".json", ".png", ".jpg", ".jpeg", ".webp", ".imf", ".imx", ".yml", ".yaml", ".md", ".txt" };
    public static async Task<int> Run(string[] args)
    {
        try
        {
            if (args.Length == 0) throw new ArgumentException("Commands: init-key, prepare, verify, self-test. See Docs/ResourceUpdates.md.");
            var options = Parse(args.Skip(1).ToArray());
            switch (args[0])
            {
                case "init-key": InitKey(options); break;
                case "prepare": await Prepare(options); break;
                case "verify": Verify(options); break;
                case "verify-manifest":
                    var verified = VerifyEnvelope(Required(options, "input"), Read<TrustedUpdateKeys>(Required(options, "public-key")), options.GetValueOrDefault("test") != "true");
                    Console.WriteLine(JsonSerializer.Serialize(new { verified.Sequence, appVersion = verified.App.Version, snapshotIds = verified.Resources.Select(r => r.SnapshotId) }, Json));
                    break;
                case "self-test": SelfTest(Required(options, "output")); break;
                default: throw new ArgumentException("Unknown command.");
            }
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine($"UpdatePublisher: {ex.Message}"); return 1; }
    }

    static Dictionary<string, string> Parse(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--") || i + 1 == args.Length || args[i + 1].StartsWith("--"))
                throw new ArgumentException("Options use --name value, including --test true.");
            if (!result.TryAdd(args[i][2..], args[++i])) throw new ArgumentException("Duplicate option.");
        }
        return result;
    }
    static string Required(Dictionary<string, string> o, string key) => o.TryGetValue(key, out var v) && v.Length > 0 ? v : throw new ArgumentException($"Missing --{key}.");
    static T Read<T>(string file) => JsonSerializer.Deserialize<T>(File.ReadAllBytes(file), Json) ?? throw new InvalidDataException($"Invalid JSON: {Path.GetFileName(file)}");
    static void WriteNew<T>(string file, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(file))!);
        using var stream = new FileStream(file, FileMode.CreateNew);
        JsonSerializer.Serialize(stream, value, Json);
    }
    static string Hash(string file) { using var f = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(f)).ToLowerInvariant(); }
    static string Id(string id)
    {
        if (!Regex.IsMatch(id, "^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$") || id.Contains("..")) throw new InvalidDataException("Invalid package/key identifier.");
        return id;
    }
    static string Relative(string root, string full) => Path.GetRelativePath(root, full).Replace('\\', '/');
    static string SafeFile(string root, string relative)
    {
        UpdateStorage.ValidateRelativePath(relative);
        if (string.IsNullOrWhiteSpace(relative) || relative.Contains('\\') || relative.Contains(':') || relative.StartsWith('/') ||
            relative.Split('/').Any(s => s is "." or ".." or "" || s.EndsWith('.') || s.EndsWith(' '))) throw new InvalidDataException("Unsafe archive path.");
        var full = Path.GetFullPath(Path.Combine(root, relative));
        if (!full.StartsWith(Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Archive path escapes its root.");
        return full;
    }
    static void InitKey(Dictionary<string, string> o)
    {
        var repo = Path.GetFullPath(Required(o, "repo"));
        var destination = Path.GetFullPath(Required(o, "private-key"));
        var test = o.GetValueOrDefault("test") == "true";
        if (!test && destination.StartsWith(repo.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Production private keys must be outside the repository.");
        var publicFile = Required(o, "public-key");
        if (File.Exists(destination) || File.Exists(publicFile)) throw new IOException("Key destination already exists; refusing overwrite.");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateBytes = key.ExportPkcs8PrivateKey();
        try
        {
            var protectedBytes = Dpapi.Protect(privateBytes);
            WriteNew(destination, new PrivateKey(Id(Required(o, "key-id")), test, Convert.ToBase64String(protectedBytes)));
            WriteNew(publicFile, new TrustedUpdateKeys { Keys = [new() { KeyId = Required(o, "key-id"), TestOnly = test, PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) }] });
        }
        finally { CryptographicOperations.ZeroMemory(privateBytes); }
        Console.WriteLine("Created DPAPI CurrentUser signing key and public registry. Private material was not printed.");
    }
    static ECDsa LoadPrivate(string path, bool production, out string keyId)
    {
        var stored = Read<PrivateKey>(path);
        if (production && stored.TestOnly) throw new InvalidOperationException("Production preparation rejects a test signing key.");
        keyId = Id(stored.KeyId);
        var plain = Dpapi.Unprotect(Convert.FromBase64String(stored.ProtectedPkcs8));
        try { var key = ECDsa.Create(); key.ImportPkcs8PrivateKey(plain, out _); if (key.KeySize != 256) throw new CryptographicException("P-256 required."); return key; }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }
    static SignedUpdateEnvelope Sign(UpdateCatalog catalog, ECDsa key, string id)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(catalog, Json);
        return new() { KeyId = id, Payload = Convert.ToBase64String(payload), Signature = Convert.ToBase64String(key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
    }
    static UpdateCatalog VerifyEnvelope(string file, TrustedUpdateKeys keys, bool production)
    {
        // Always use the client's authoritative verifier first, including its limits and path policy.
        UpdateSignature.Verify(File.ReadAllBytes(file), keys.Keys, allowTestKeys: !production);
        var envelope = Read<SignedUpdateEnvelope>(file);
        var trusted = keys.Keys.SingleOrDefault(k => k.KeyId == envelope.KeyId) ?? throw new CryptographicException("Unknown release signing key.");
        if (production && trusted.TestOnly) throw new CryptographicException("Production verification rejects test keys.");
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(trusted.PublicKey), out _);
        var bytes = Convert.FromBase64String(envelope.Payload);
        if (key.KeySize != 256 || !key.VerifyData(bytes, Convert.FromBase64String(envelope.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new CryptographicException("Invalid release signature.");
        var catalog = JsonSerializer.Deserialize<UpdateCatalog>(bytes, Json) ?? throw new InvalidDataException("Invalid release catalog.");
        ValidateCatalog(catalog);
        return catalog;
    }
    static void ValidateCatalog(UpdateCatalog c)
    {
        UpdateSignature.ValidateCatalog(c);
        if (c.SchemaVersion != 1 || c.Sequence < 1 || c.Resources.Count == 0) throw new InvalidDataException("Invalid catalog version, sequence, or empty resources.");
        FourPartVersion(c.App.Version);
        RequireGithub(c.App.Url, false);
        var identities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in c.Resources)
        {
            Id(r.SnapshotId); Id(r.BaselineId);
            if (r.Sequence < 1 || r.Sequence > c.Sequence || r.Packages.Count(p => p.Kind == "map-data") != 1) throw new InvalidDataException("Each snapshot requires exactly one map-data package and valid sequence.");
            FourPartVersion(r.MinAppVersion);
            if (r.MaxAppVersion is not null && Version.Parse(r.MaxAppVersion) < Version.Parse(r.MinAppVersion)) throw new InvalidDataException("Invalid compatibility range.");
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in r.Packages)
            {
                Id(p.Id); FourPartVersion(p.Version);
                if (!seen.Add(p.Id) || p.Kind is not ("map-data" or "tile" or "candidate") || p.Size <= 0 || !Regex.IsMatch(p.Sha256, "^[a-fA-F0-9]{64}$") || p.Files.Count == 0) throw new InvalidDataException("Invalid or duplicate package.");
                RequireGithub(p.Url, true);
                var identity = p.Id + "/" + p.Version;
                if (identities.TryGetValue(identity, out var hash) && hash != p.Sha256) throw new InvalidDataException("Same package version has different content.");
                identities[identity] = p.Sha256;
                var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var f in p.Files)
                {
                    SafeFile(Path.GetTempPath(), f.Path);
                    if (!AllowedExtensions.Contains(Path.GetExtension(f.Path)) || !paths.Add(f.Path) || f.Size < 0 || !Regex.IsMatch(f.Sha256, "^[a-fA-F0-9]{64}$")) throw new InvalidDataException("Invalid package file list.");
                }
            }
        }
    }
    static void FourPartVersion(string value)
    {
        if (!Regex.IsMatch(value, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$") || !Version.TryParse(value, out var version) || version.Major > 65535 || version.Minor > 65535 || version.Build > 65535 || version.Revision > 65535)
            throw new InvalidDataException("Versions must contain four nonnegative 16-bit numeric components.");
    }
    static void RequireGithub(string value, bool asset)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.Host != "github.com" ||
            !uri.AbsolutePath.StartsWith(asset ? "/kahvia-d/WWMAP-TOOLS/releases/download/" : "/kahvia-d/WWMAP-TOOLS/releases/", StringComparison.Ordinal) || uri.UserInfo.Length != 0 || uri.Query.Length != 0)
            throw new InvalidDataException("Only this repository's GitHub Releases URLs are permitted.");
    }
    static ResourcePackage Package(string source, string output, SnapshotPackage package, string baseUrl)
    {
        var files = Directory.GetFiles(source, "*", SearchOption.AllDirectories).OrderBy(p => Relative(source, p), StringComparer.Ordinal).ToArray();
        if (files.Length == 0) throw new InvalidDataException("Empty resource package.");
        var manifest = new List<ResourceFile>();
        foreach (var file in files)
        {
            UpdateStorage.RejectLink(file);
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0 || !AllowedExtensions.Contains(Path.GetExtension(file))) throw new InvalidDataException($"Unapproved resource file: {Relative(source, file)}");
            manifest.Add(new() { Path = Relative(source, file), Size = new FileInfo(file).Length, Sha256 = Hash(file) });
        }
        var name = $"{Id(package.Id)}-{Id(package.Version)}.zip";
        var destination = Path.Combine(output, "packages", name);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        using (var archive = new ZipArchive(new FileStream(destination, FileMode.CreateNew), ZipArchiveMode.Create))
        {
            foreach (var file in manifest)
            {
                var entry = archive.CreateEntry(file.Path, CompressionLevel.Optimal); entry.LastWriteTime = ZipEpoch;
                using var input = File.OpenRead(SafeFile(source, file.Path)); using var target = entry.Open(); input.CopyTo(target);
            }
        }
        var fileArchives = new List<ResourceFileArchive>();
        foreach (var file in manifest)
        {
            var sourceFile = SafeFile(source, file.Path);
            // Content-addressed names allow unchanged files to remain at their
            // previous Release URL even when the containing package changes.
            // The path suffix prevents two equal byte streams at different paths
            // from sharing a ZIP whose sole entry name would be wrong.
            var pathHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(file.Path)))[..16].ToLowerInvariant();
            var archiveName = "file-" + file.Sha256.ToLowerInvariant() + "-" + pathHash + ".zip";
            var archivePath = Path.Combine(output, "files", archiveName);
            if (!File.Exists(archivePath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(archivePath)!);
                using var archive = new ZipArchive(new FileStream(archivePath, FileMode.CreateNew), ZipArchiveMode.Create);
                var entry = archive.CreateEntry(file.Path, CompressionLevel.Optimal); entry.LastWriteTime = ZipEpoch;
                using var input = File.OpenRead(sourceFile); using var target = entry.Open(); input.CopyTo(target);
            }
            fileArchives.Add(new() { Path = file.Path, Url = baseUrl + "/" + archiveName, Size = new FileInfo(archivePath).Length, Sha256 = Hash(archivePath) });
        }
        return new() { Id = package.Id, Version = package.Version, Kind = package.Kind, Url = baseUrl + "/" + name,
            Size = new FileInfo(destination).Length, Sha256 = Hash(destination), Files = manifest, FileArchives = fileArchives };
    }
    static void VerifyPackage(string file, ResourcePackage p)
    {
        if (new FileInfo(file).Length != p.Size || !string.Equals(Hash(file), p.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Package hash or size mismatch: {p.Id}");
        using var zip = ZipFile.OpenRead(file);
        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in zip.Entries)
        {
            SafeFile(Path.GetTempPath(), e.FullName);
            if (!entries.TryAdd(e.FullName, e) || (e.ExternalAttributes >> 16 & 0xF000) == 0xA000) throw new InvalidDataException("Duplicate ZIP entry or symbolic link.");
        }
        if (entries.Count != p.Files.Count) throw new InvalidDataException("Unexpected or missing ZIP files.");
        foreach (var f in p.Files)
        {
            if (!entries.TryGetValue(f.Path, out var e) || e.Length != f.Size) throw new InvalidDataException("ZIP file size mismatch.");
            using var stream = e.Open();
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(stream)), f.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("ZIP file hash mismatch.");
        }
    }
    static async Task Prepare(Dictionary<string, string> o)
    {
        var output = Path.GetFullPath(Required(o, "output"));
        if (Directory.Exists(output) && Directory.EnumerateFileSystemEntries(output).Any()) throw new IOException("Output directory must be empty; reviewed artifacts are immutable.");
        Directory.CreateDirectory(output);
        var appRoot = Path.GetFullPath(Required(o, "app-root"));
        var assets = Path.Combine(appRoot, "Assets");
        var snapshot = Read<ResourceSnapshot>(Path.Combine(assets, "Updates", "bundled-snapshot.json"));
        var build = Read<BuildInfo>(Path.Combine(appRoot, "build-info.json"));
        using var provenance = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(appRoot, "build-info.json")));
        var sourceDirty = !provenance.RootElement.TryGetProperty("sourceDirty", out var dirty) || dirty.GetBoolean();
        var sourceTreeSha256 = provenance.RootElement.TryGetProperty("sourceTreeSha256", out var treeHash) ? treeHash.GetString() : null;
        if (!Regex.IsMatch(build.SourceCommit, "^[a-f0-9]{40}$") || build.BaselineId != snapshot.BaselineId) throw new InvalidDataException("Build metadata must have a real source SHA and matching baseline.");
        var production = o.GetValueOrDefault("test") != "true";
        using var key = LoadPrivate(Required(o, "private-key"), production, out var keyId);
        var keys = Read<TrustedUpdateKeys>(Required(o, "public-key"));
        var trusted = keys.Keys.Single(k => k.KeyId == keyId);
        if (!CryptographicOperations.FixedTimeEquals(key.ExportSubjectPublicKeyInfo(), Convert.FromBase64String(trusted.PublicKey))) throw new CryptographicException("Signing key does not match public registry.");
        var sequence = long.Parse(Required(o, "sequence"));
        var version = Id(Required(o, "resource-version"));
        var tag = Id(Required(o, "tag"));
        var baseUrl = "https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/" + tag;
        UpdateCatalog? previous = null;
        if (o.TryGetValue("previous", out var previousFile))
        {
            previous = VerifyEnvelope(previousFile, keys, production);
            if (previous.Sequence >= sequence) throw new InvalidDataException("Catalog sequence must increase.");
        }
        var packages = new List<ResourcePackage>();
        foreach (var p in snapshot.Packages)
        {
            var source = SafeFile(assets, p.Directory.Replace('\\', '/'));
            if (p.Kind == "tile")
            {
                using var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(source, "manifest.json")));
                if (!manifest.RootElement.GetProperty("referenceVerification").GetProperty("passed").GetBoolean()) throw new InvalidDataException("Cannot publish an unverified tile pack.");
            }
            var prior = previous?.Resources.SelectMany(r => r.Packages).LastOrDefault(q => q.Id == p.Id);
            if (prior is not null && prior.Kind != p.Kind) throw new InvalidDataException("A package ID cannot change its resource kind.");
            var built = Package(source, output, p with { Version = version }, baseUrl);
            if (prior?.FileArchives is not null)
            {
                var priorFiles = prior.FileArchives.ToDictionary(a => a.Path, StringComparer.OrdinalIgnoreCase);
                built = built with { FileArchives = built.FileArchives!.Select(a =>
                    priorFiles.TryGetValue(a.Path, out var old) && old.Sha256.Equals(a.Sha256, StringComparison.OrdinalIgnoreCase) && old.Size == a.Size ? old : a).ToList() };
            }
            // Identical file bytes retain their old package identity and URL, enabling true differential updates.
            if (prior is not null && FileListsEqual(prior.Files, built.Files))
            {
                var generated = Path.Combine(output, "packages", $"{built.Id}-{built.Version}.zip");
                if (!string.Equals(prior.Sha256, built.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unchanged source produced a different archive; use the matching deterministic packer.");
                var retained = Path.Combine(output, "packages", $"{prior.Id}-{prior.Version}.zip");
                if (!string.Equals(generated, retained, StringComparison.OrdinalIgnoreCase)) File.Move(generated, retained);
                built = prior;
            }
            var sameIdentity = previous?.Resources.SelectMany(r => r.Packages).FirstOrDefault(q => q.Id == built.Id && q.Version == built.Version);
            if (sameIdentity is not null && (sameIdentity.Sha256 != built.Sha256 || !FileArchivesEqual(sameIdentity.FileArchives, built.FileArchives))) throw new InvalidDataException("Package version reuse with different content or file archives is forbidden.");
            packages.Add(built);
        }
        var release = new ResourceRelease { SnapshotId = "resources-" + version, Sequence = sequence, BaselineId = build.BaselineId,
            MinAppVersion = o.GetValueOrDefault("min-app-version", build.AppVersion), MaxAppVersion = o.GetValueOrDefault("max-app-version"),
            Notes = o.TryGetValue("notes-file", out var notesFile) ? File.ReadAllText(notesFile) : "地图资源更新", Packages = packages };
        var resources = previous?.Resources.Where(r => r.BaselineId != release.BaselineId).ToList() ?? [];
        resources.Add(release);
        var app = previous?.App ?? new ProgramRelease { Version = build.AppVersion, Url = "https://github.com/kahvia-d/WWMAP-TOOLS/releases/tag/" + tag, Notes = "首次支持程序与地图资源更新。" };
        if (o.GetValueOrDefault("program-release") == "true")
        {
            ProgramPackage? program = null;
            if (o.TryGetValue("program-zip", out var programZip))
            {
                program = await ProgramPackageValidation.DescribeAsync(programZip, build, baseUrl + "/" + Uri.EscapeDataString(Path.GetFileName(programZip)));
                // Validate the exact ZIP bytes to be signed, rather than trusting a neighboring report.
                var verifiedProgram = Path.Combine(output, "program-verification");
                await ProgramPackageValidation.ExtractAsync(programZip, verifiedProgram, program);
                await ProgramPackageValidation.VerifyDirectoryAsync(verifiedProgram, new ProgramRelease { Version = build.AppVersion, Package = program });
                if (previous?.App.Version == build.AppVersion && previous.App.Package is not null && previous.App.Package.Sha256 != program.Sha256)
                    throw new InvalidDataException("The published program version is immutable. Increment the version before rebuilding.");
            }
            else if (production) throw new InvalidDataException("Program releases require --program-zip with the complete tested application archive.");
            app = new() { Version = build.AppVersion, Url = "https://github.com/kahvia-d/WWMAP-TOOLS/releases/tag/" + tag, Notes = release.Notes, Package = program };
        }
        var catalog = new UpdateCatalog { Sequence = sequence, App = app, Resources = resources };
        ValidateCatalog(catalog);
        var signedFile = Path.Combine(output, "update.json");
        WriteNew(signedFile, Sign(catalog, key, keyId));
        VerifyEnvelope(signedFile, keys, production);
        foreach (var p in packages) VerifyPackage(Path.Combine(output, "packages", $"{p.Id}-{p.Version}.zip"), p);
        foreach (var archive in packages.SelectMany(p => p.FileArchives ?? []).Where(a => new Uri(a.Url).AbsolutePath.StartsWith(new Uri(baseUrl).AbsolutePath + "/", StringComparison.Ordinal))) VerifyFileArchive(Path.Combine(output, "files", Path.GetFileName(new Uri(archive.Url).AbsolutePath)), archive);
        // Validate source snapshot using the same native parser used by installed clients.
        var candidate = snapshot with { FormatVersion = 2, SnapshotId = release.SnapshotId, Sequence = sequence, Bundled = false,
            MinAppVersion = release.MinAppVersion, MaxAppVersion = release.MaxAppVersion,
            BaselineRoot = assets, MapDataRoot = Path.Combine(assets, snapshot.MapDataRoot),
            Packages = snapshot.Packages.Select((p, i) => p with { Directory = Path.Combine(assets, p.Directory), Version = packages[i].Version, Sha256 = packages[i].Sha256, Files = packages[i].Files }).ToList() };
        var candidateFile = Path.Combine(output, "preflight-snapshot.json");
        WriteNew(candidateFile, candidate);
        var nativePassed = false;
        if (o.TryGetValue("core-host", out var host))
        {
            var start = new ProcessStartInfo(Path.GetFullPath(host)) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = appRoot };
            start.ArgumentList.Add("--check-resource-snapshot"); start.ArgumentList.Add(candidateFile);
            using var process = Process.Start(start) ?? throw new IOException("Could not start CoreHost.");
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            try { await process.WaitForExitAsync(timeout.Token); } catch { process.Kill(true); throw; }
            File.WriteAllText(Path.Combine(output, "native-check.stdout.json"), await stdout);
            File.WriteAllText(Path.Combine(output, "native-check.stderr.log"), await stderr);
            if (process.ExitCode != 0) throw new InvalidDataException("Native snapshot preflight failed; see output logs.");
            nativePassed = true;
        }
        if (production && !nativePassed) throw new InvalidOperationException("Production preparation requires --core-host and successful native preflight.");
        var offline = Path.Combine(output, $"resources-{version}-offline.zip");
        using (var zip = new ZipArchive(new FileStream(offline, FileMode.CreateNew), ZipArchiveMode.Create))
        {
            AddFile(zip, signedFile, "update.json", CompressionLevel.Optimal);
            foreach (var p in packages) { var name = $"{p.Id}-{p.Version}.zip"; AddFile(zip, Path.Combine(output, "packages", name), "packages/" + name, CompressionLevel.NoCompression); }
        }
        if (new FileInfo(offline).Length >= 2L * 1024 * 1024 * 1024 || packages.Any(p => p.Size >= 2L * 1024 * 1024 * 1024))
            throw new InvalidOperationException("A GitHub Releases attachment must be smaller than 2 GiB. Split the resource distribution before publishing this release.");
        WriteNew(Path.Combine(output, "release-report.json"), new { formatVersion = 1, production, sourceCommit = build.SourceCommit, sourceDirty, sourceTreeSha256, appVersion = build.AppVersion, baselineId = build.BaselineId,
            tag, sequence, snapshotId = release.SnapshotId, nativePassed, signedManifestSha256 = Hash(signedFile),
            assets = packages.Select(p => new { name = $"{p.Id}-{p.Version}.zip", sha256 = p.Sha256, size = p.Size, url = p.Url }).ToArray(),
            fileAssets = packages.SelectMany(p => p.FileArchives ?? []).GroupBy(a => a.Sha256, StringComparer.OrdinalIgnoreCase).Select(g => new { name = Path.GetFileName(new Uri(g.First().Url).AbsolutePath), sha256 = g.First().Sha256, size = g.First().Size, url = g.First().Url }).ToArray(),
            manifestBytes = new FileInfo(signedFile).Length,
            offline = new { name = Path.GetFileName(offline), size = new FileInfo(offline).Length, sha256 = Hash(offline) } });
        Console.WriteLine($"Prepared {packages.Count} signed resource packages, offline archive and validation report. No remote publication occurred.");
    }
    static void VerifyFileArchive(string path, ResourceFileArchive archive)
    {
        if (new FileInfo(path).Length != archive.Size || !string.Equals(Hash(path), archive.Sha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("File archive hash or size mismatch.");
        using var zip = ZipFile.OpenRead(path);
        if (zip.Entries.Count != 1 || zip.Entries[0].FullName != archive.Path) throw new InvalidDataException("File archive has an unexpected entry.");
    }
    static bool FileListsEqual(List<ResourceFile> a, List<ResourceFile> b) => a.Count == b.Count && a.OrderBy(x => x.Path, StringComparer.Ordinal).SequenceEqual(b.OrderBy(x => x.Path, StringComparer.Ordinal));
    static bool FileArchivesEqual(List<ResourceFileArchive>? a, List<ResourceFileArchive>? b)
    {
        if (a is null || b is null) return a is null && b is null;
        return a.Count == b.Count && a.OrderBy(x => x.Path, StringComparer.Ordinal).Select(x => (x.Path, x.Size, x.Sha256)).SequenceEqual(b.OrderBy(x => x.Path, StringComparer.Ordinal).Select(x => (x.Path, x.Size, x.Sha256)));
    }
    static void AddFile(ZipArchive zip, string source, string name, CompressionLevel compression)
    {
        var entry = zip.CreateEntry(name, compression); entry.LastWriteTime = ZipEpoch;
        using var input = File.OpenRead(source); using var output = entry.Open(); input.CopyTo(output);
    }
    static void Verify(Dictionary<string, string> o)
    {
        var root = Path.GetFullPath(Required(o, "input"));
        var catalog = VerifyEnvelope(Path.Combine(root, "update.json"), Read<TrustedUpdateKeys>(Required(o, "public-key")), o.GetValueOrDefault("test") != "true");
        var selected = o.TryGetValue("snapshot-id", out var id) ? catalog.Resources.Single(r => r.SnapshotId == id) : catalog.Resources.OrderByDescending(r => r.Sequence).First();
        foreach (var p in selected.Packages) VerifyPackage(Path.Combine(root, "packages", $"{p.Id}-{p.Version}.zip"), p);
        Console.WriteLine($"Verified signature and {selected.Packages.Count} complete resource packages for {selected.SnapshotId}.");
    }
    static void SelfTest(string root)
    {
        root = Path.GetFullPath(root);
        if (Directory.Exists(root)) throw new IOException("Self-test output must not exist.");
        Directory.CreateDirectory(root);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var keys = new TrustedUpdateKeys { Keys = [new() { KeyId = "fixture", TestOnly = true, PublicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()) }] };
        var source = Path.Combine(root, "source"); Directory.CreateDirectory(source); File.WriteAllText(Path.Combine(source, "sample.json"), "{\"id\":\"stable-point\"}");
        var p = Package(source, root, new() { Id = "map-data", Version = "2026.9.9.1", Kind = "map-data" }, "https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/test");
        VerifyPackage(Path.Combine(root, "packages", "map-data-2026.9.9.1.zip"), p);
        var catalog = new UpdateCatalog { Sequence = 1, App = new() { Version = "2026.9.9.1", Url = "https://github.com/kahvia-d/WWMAP-TOOLS/releases/tag/test" }, Resources = [new() { SnapshotId = "test-1", Sequence = 1, BaselineId = "baseline", MinAppVersion = "2026.9.9.1", Packages = [p] }] };
        var envelopeFile = Path.Combine(root, "update.json"); WriteNew(envelopeFile, Sign(catalog, key, "fixture"));
        VerifyEnvelope(envelopeFile, keys, false);
        var passed = new List<string> { "deterministic resource package and file hashes", "P-256 signed envelope round-trip" };
        void Reject(string name, Action action) { try { action(); } catch { passed.Add(name); return; } throw new Exception("Expected rejection: " + name); }
        Reject("test signing key rejected for production", () => VerifyEnvelope(envelopeFile, keys, true));
        var altered = Read<SignedUpdateEnvelope>(envelopeFile) with { Payload = Convert.ToBase64String("{}"u8.ToArray()) };
        var alteredPath = Path.Combine(root, "tampered.json"); WriteNew(alteredPath, altered);
        Reject("tampered payload rejected", () => VerifyEnvelope(alteredPath, keys, false));
        Reject("path traversal rejected", () => SafeFile(root, "../escape.json"));
        Reject("executable extension rejected", () => { File.WriteAllText(Path.Combine(source, "bad.exe"), "bad"); Package(source, Path.Combine(root, "bad"), new() { Id = "map-data", Version = "2", Kind = "map-data" }, "https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/test"); });
        Reject("unknown release host rejected", () => RequireGithub("https://example.com/kahvia-d/WWMAP-TOOLS/releases/download/test/a.zip", true));
        Reject("missing map-data rejected", () => ValidateCatalog(catalog with { Resources = [catalog.Resources[0] with { Packages = [] }] }));
        Reject("reserved Windows filename rejected", () => SafeFile(root, "CON.json"));
        var originalZip = Path.Combine(root, "packages", "map-data-2026.9.9.1.zip");
        var duplicateZip = Path.Combine(root, "duplicate.zip");
        File.Copy(originalZip, duplicateZip);
        using (var zip = ZipFile.Open(duplicateZip, ZipArchiveMode.Update)) { using var extra = zip.CreateEntry("sample.json").Open(); extra.Write("{}"u8); }
        Reject("duplicate archive entry rejected", () => VerifyPackage(duplicateZip, p with { Size = new FileInfo(duplicateZip).Length, Sha256 = Hash(duplicateZip) }));
        var missingZip = Path.Combine(root, "missing.zip");
        using (var zip = ZipFile.Open(missingZip, ZipArchiveMode.Create)) { }
        Reject("missing archive file rejected", () => VerifyPackage(missingZip, p with { Size = new FileInfo(missingZip).Length, Sha256 = Hash(missingZip) }));
        Reject("modified archive hash rejected", () => VerifyPackage(duplicateZip, p));
        var protectedBytes = Dpapi.Protect("fixture-secret"u8.ToArray());
        if (!Dpapi.Unprotect(protectedBytes).AsSpan().SequenceEqual("fixture-secret"u8)) throw new Exception("DPAPI round-trip failed.");
        passed.Add("DPAPI CurrentUser round-trip");
        // A real producer round-trip proves unchanged map-data keeps its identity when only a feature changes.
        var app = Path.Combine(root, "fixture-app");
        Directory.CreateDirectory(Path.Combine(app, "Assets", "KuroMap"));
        Directory.CreateDirectory(Path.Combine(app, "Assets", "candidate"));
        File.WriteAllText(Path.Combine(app, "Assets", "KuroMap", "points.json"), "{\"id\":\"stable-point\"}");
        File.WriteAllText(Path.Combine(app, "Assets", "candidate", "visual-index.imx"), "fixture index 1");
        WriteNew(Path.Combine(app, "build-info.json"), new { appVersion = "2026.9.9.1", baselineId = "test-baseline", sourceCommit = new string('a', 40), sourceDirty = true });
        WriteNew(Path.Combine(app, "Assets", "Updates", "bundled-snapshot.json"), new ResourceSnapshot { SnapshotId = "bundled-test", BaselineId = "test-baseline", BaselineRoot = ".", MapDataRoot = "KuroMap", Bundled = true,
            Packages = [new() { Id = "map-data", Kind = "map-data", Version = "2026.9.9.1", Directory = "KuroMap" }, new() { Id = "fixture-feature", Kind = "candidate", Version = "2026.9.9.1", Directory = "candidate" }] });
        var privateFile = Path.Combine(root, "fixture-private.json");
        var publicFile = Path.Combine(root, "fixture-public.json");
        var privateBytes = key.ExportPkcs8PrivateKey();
        try { WriteNew(privateFile, new PrivateKey("fixture", true, Convert.ToBase64String(Dpapi.Protect(privateBytes)))); }
        finally { CryptographicOperations.ZeroMemory(privateBytes); }
        WriteNew(publicFile, keys);
        var options = new Dictionary<string, string> { ["app-root"] = app, ["private-key"] = privateFile, ["public-key"] = publicFile, ["output"] = Path.Combine(root, "first"), ["sequence"] = "1", ["resource-version"] = "2026.9.9.1", ["tag"] = "fixture-1", ["test"] = "true" };
        Prepare(options).GetAwaiter().GetResult();
        File.WriteAllText(Path.Combine(app, "Assets", "candidate", "visual-index.imx"), "fixture index 2");
        options["previous"] = Path.Combine(root, "first", "update.json"); options["output"] = Path.Combine(root, "second"); options["sequence"] = "2"; options["resource-version"] = "2026.9.9.2"; options["tag"] = "fixture-2";
        Prepare(options).GetAwaiter().GetResult();
        var second = VerifyEnvelope(Path.Combine(root, "second", "update.json"), keys, false);
        var preflight = Read<ResourceSnapshot>(Path.Combine(root, "second", "preflight-snapshot.json"));
        if (preflight.FormatVersion != 2 || preflight.Bundled || preflight.MinAppVersion != second.Resources.Single().MinAppVersion || preflight.MaxAppVersion != second.Resources.Single().MaxAppVersion)
            throw new Exception("Native preflight must carry the external snapshot schema and program compatibility bounds.");
        passed.Add("external v2 preflight preserves signed program compatibility bounds");
        if (second.Resources.Single().Packages.Single(p => p.Id == "map-data").Version != "2026.9.9.1" || second.Resources.Single().Packages.Single(p => p.Id == "fixture-feature").Version != "2026.9.9.2") throw new Exception("Differential package identity preservation failed.");
        if (second.App.Url != "https://github.com/kahvia-d/WWMAP-TOOLS/releases/tag/fixture-1") throw new Exception("Resource-only release changed program identity.");
        using (var offline = ZipFile.OpenRead(Path.Combine(root, "second", "resources-2026.9.9.2-offline.zip")))
            if (offline.Entries.Count != 3 || offline.GetEntry("update.json") is null || offline.GetEntry("packages/map-data-2026.9.9.1.zip") is null) throw new Exception("Offline archive is incomplete.");
        passed.Add("feature-only publish retains unchanged map-data version/hash and old program release");
        passed.Add("offline archive includes signed catalog and all selected packages");
        foreach (var file in ProgramPackageValidation.RequiredFiles)
        {
            var path = Path.Combine(app, file); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            if (!File.Exists(path)) File.WriteAllText(path, "fixture:" + file);
        }
        var programZip = Path.Combine(root, "fixture-program.zip"); ZipFile.CreateFromDirectory(app, programZip);
        options["previous"] = Path.Combine(root, "second", "update.json"); options["output"] = Path.Combine(root, "program"); options["sequence"] = "3"; options["resource-version"] = "2026.9.9.3";
        options["program-release"] = "true"; options["program-zip"] = programZip;
        Prepare(options).GetAwaiter().GetResult();
        var programCatalog = VerifyEnvelope(Path.Combine(root, "program", "update.json"), keys, false);
        if (programCatalog.App.Package?.Sha256 != Hash(programZip) || programCatalog.App.Package.Files.Count != Directory.GetFiles(app, "*", SearchOption.AllDirectories).Length)
            throw new Exception("Program ZIP was not completely bound by the signature.");
        passed.Add("program release signs archive hash and complete executable inventory");
        options["previous"] = Path.Combine(root, "program", "update.json"); options["output"] = Path.Combine(root, "retained-program"); options["sequence"] = "4"; options["resource-version"] = "2026.9.9.4";
        options.Remove("program-release"); options.Remove("program-zip");
        Prepare(options).GetAwaiter().GetResult();
        if (VerifyEnvelope(Path.Combine(root, "retained-program", "update.json"), keys, false).App.Package?.Sha256 != programCatalog.App.Package!.Sha256) throw new Exception("Resource-only release lost signed program metadata.");
        passed.Add("resource-only release preserves signed program inventory");
        options["output"] = Path.Combine(root, "test-key-production"); options["test"] = "false";
        Reject("production prepare rejects test private key", () => Prepare(options).GetAwaiter().GetResult());
        WriteNew(Path.Combine(root, "test-report.json"), new { passed = passed.Count, tests = passed });
        Console.WriteLine($"PASS {passed.Count} publisher checks.");
    }
    sealed record PrivateKey(string KeyId, bool TestOnly, string ProtectedPkcs8);
}

static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)] struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
    public static byte[] Protect(byte[] input) => Transform(input, true);
    public static byte[] Unprotect(byte[] input) => Transform(input, false);
    static byte[] Transform(byte[] input, bool encrypt)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Signing key protection requires Windows DPAPI CurrentUser.");
        var blob = new Blob { Length = input.Length, Data = Marshal.AllocHGlobal(input.Length) };
        Marshal.Copy(input, 0, blob.Data, input.Length);
        try
        {
            Blob output;
            var ok = encrypt ? CryptProtectData(ref blob, "WWMAP-TOOLS update signing key", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref blob, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new CryptographicException(Marshal.GetLastWin32Error());
            try { var bytes = new byte[output.Length]; Marshal.Copy(output.Data, bytes, 0, bytes.Length); return bytes; }
            finally { for (var i = 0; i < output.Length; i++) Marshal.WriteByte(output.Data, i, 0); LocalFree(output.Data); }
        }
        finally { for (var i = 0; i < input.Length; i++) Marshal.WriteByte(blob.Data, i, 0); Marshal.FreeHGlobal(blob.Data); }
    }
}
