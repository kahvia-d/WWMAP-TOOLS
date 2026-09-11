#nullable enable
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace IMao_WinUI.Core.Updates;

public sealed record UpdateCheckResult
{
    public UpdateCatalog? Catalog { get; init; }
    public ResourceRelease? Resource { get; init; }
    public ProgramRelease? AppUpdate { get; init; }
    public bool RequiresAppUpgrade { get; init; }
    public bool Skipped { get; init; }
    public DateTimeOffset? LastChecked { get; init; }
    public string Message { get; init; } = "";
}

public sealed class UpdateService : IDisposable
{
    public static readonly Uri StableUri = new("https://raw.githubusercontent.com/kahvia-d/WWMAP-TOOLS/main/updates/stable.json");
    private readonly BuildInfo _build;
    private readonly TrustedUpdateKey[] _keys;
    private readonly ResourceSnapshotService _snapshots;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly bool _allowTestKeys;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<long> _freeSpace;
    private readonly string _statePath;
    private UpdaterState _state;
    private byte[]? _checkedEnvelope;
    private readonly string _initializationError;
    private readonly string _stateReadError = "";

    public UpdateService(BuildInfo build, IEnumerable<TrustedUpdateKey> keys, ResourceSnapshotService snapshots,
        HttpClient? httpClient = null, bool allowTestKeys = false, Func<DateTimeOffset>? clock = null, Func<long>? availableBytes = null, string? initializationError = null)
    {
        _build = build;
        UpdateSignature.RequireVersion(build.AppVersion);
        _keys = keys.ToArray();
        _snapshots = snapshots;
        _allowTestKeys = allowTestKeys;
        _initializationError = initializationError ?? "";
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _freeSpace = availableBytes ?? (() => new DriveInfo(Path.GetPathRoot(_snapshots.Root)!).AvailableFreeSpace);
        _statePath = Path.Combine(snapshots.Root, "update-state.json");
        try { _state = LoadState(); }
        catch (InvalidDataException ex) { _stateReadError = ex.Message; _state = new UpdaterState { AutoCheckEnabled = false, LastError = ex.Message }; }
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(20), PooledConnectionLifetime = TimeSpan.FromMinutes(5) }) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public UpdateCheckResult? LastCheckResult { get; private set; }
    public DateTimeOffset? LastChecked => _state.LastAttempt;
    public bool AutoCheckEnabled => string.IsNullOrEmpty(_initializationError) && _state.AutoCheckEnabled;
    public string InitializationError => string.IsNullOrEmpty(_initializationError) ? _stateReadError : _initializationError;
    public string LastError => string.IsNullOrEmpty(_initializationError) ? _state.LastError : _initializationError;

    public async Task PrepareProgramAsync(ProgramUpdateStore programs, IProgress<UpdateProgress>? progress = null, CancellationToken ct = default)
    {
        EnsureAvailable();
        if (_checkedEnvelope is null) throw new InvalidOperationException("请先检查更新。");
        await using var gate = await UpdateStorage.LockAsync(_snapshots.Root, ct).ConfigureAwait(false);
        _state = LoadState();
        var envelope = _checkedEnvelope.ToArray();
        var catalog = UpdateSignature.Verify(envelope, _keys, _allowTestKeys);
        AcceptSequence(catalog, envelope);
        if (UpdateSignature.RequireVersion(catalog.App.Version) <= UpdateSignature.RequireVersion(_build.AppVersion))
            throw new InvalidOperationException("没有比当前程序更新的版本。");
        await programs.PrepareAsync(envelope, async (package, output, token) =>
        {
            using var response = await GetResponseAsync(new Uri(package.Url), token).ConfigureAwait(false);
            if (response.Content.Headers.ContentLength is long size && size != package.Size) throw new InvalidDataException("程序包下载大小与签名清单不符。");
            await using var input = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            await CopyVerifiedAsync(input, output, package.Size, package.Sha256,
                n => progress?.Report(new UpdateProgress("下载新版程序", n, package.Size)), token).ConfigureAwait(false);
        }, progress, ct).ConfigureAwait(false);
    }

    public async Task SetAutoCheckEnabledAsync(bool enabled, CancellationToken ct = default)
    {
        EnsureAvailable();
        await using var gate = await UpdateStorage.LockAsync(_snapshots.Root, ct).ConfigureAwait(false);
        _state = LoadState();
        _state.AutoCheckEnabled = enabled;
        await UpdateStorage.WriteAsync(_statePath, _state, ct).ConfigureAwait(false);
    }

    public async Task<UpdateCheckResult> CheckAsync(bool automatic = false, CancellationToken ct = default)
    {
        EnsureAvailable();
        await using var gate = await UpdateStorage.LockAsync(_snapshots.Root, ct).ConfigureAwait(false);
        _state = LoadState();
        var now = _clock();
        if (automatic && (!_state.AutoCheckEnabled || (_state.LastAttempt is not null && now - _state.LastAttempt.Value < TimeSpan.FromHours(24))))
            return new UpdateCheckResult { Skipped = true, LastChecked = _state.LastAttempt, Message = "尚未到自动检查时间。" };
        _state.LastAttempt = now;
        _state.LastError = "";
        _checkedEnvelope = null;
        LastCheckResult = null;
        await UpdateStorage.WriteAsync(_statePath, _state, ct).ConfigureAwait(false);
        try
        {
            var bytes = await DownloadManifestAsync(ct).ConfigureAwait(false);
            var catalog = UpdateSignature.Verify(bytes, _keys, _allowTestKeys);
            AcceptSequence(catalog, bytes);
            var result = MakeResult(catalog);
            await UpdateStorage.WriteAsync(_statePath, _state, ct).ConfigureAwait(false);
            _checkedEnvelope = bytes;
            return LastCheckResult = result;
        }
        catch (Exception ex)
        {
            _state.LastError = ex is OperationCanceledException ? "更新检查已取消。" : ex.Message;
            await UpdateStorage.WriteAsync(_statePath, _state, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public async Task InstallAsync(IProgress<UpdateProgress>? progress = null, CancellationToken ct = default)
    {
        EnsureAvailable();
        if (_checkedEnvelope is null) throw new InvalidOperationException("请先检查更新。");
        await using var gate = await UpdateStorage.LockAsync(_snapshots.Root, ct).ConfigureAwait(false);
        _state = LoadState();
        var catalog = UpdateSignature.Verify(_checkedEnvelope, _keys, _allowTestKeys);
        AcceptSequence(catalog, _checkedEnvelope);
        var release = SelectCompatible(catalog) ?? throw new InvalidOperationException("没有与当前程序兼容的资源更新。");
        if (release.SnapshotId == _snapshots.Current.SnapshotId || release.Sequence <= _snapshots.Current.Sequence)
            throw new InvalidOperationException("当前资源已经是此清单中的最新兼容版本。");
        await InstallReleaseAsync(release, null, progress, ct).ConfigureAwait(false);
    }

    public async Task ImportOfflineAsync(string zipPath, IProgress<UpdateProgress>? progress = null, CancellationToken ct = default)
    {
        EnsureAvailable();
        await using var gate = await UpdateStorage.LockAsync(_snapshots.Root, ct).ConfigureAwait(false);
        _state = LoadState();
        await using var input = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var zip = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: true);
        var entries = ReadArchiveEntries(zip);
        if (!entries.TryGetValue("update.json", out var manifest) || manifest.Length > UpdateSignature.MaxManifestBytes) throw new InvalidDataException("离线包缺少有效的签名清单。");
        byte[] envelope;
        await using (var manifestInput = manifest.Open()) envelope = await ReadBoundedAsync(manifestInput, UpdateSignature.MaxManifestBytes, ct).ConfigureAwait(false);
        var catalog = UpdateSignature.Verify(envelope, _keys, _allowTestKeys);
        AcceptSequence(catalog, envelope);
        var release = SelectCompatible(catalog) ?? throw new InvalidOperationException("离线包与当前程序不兼容，请先升级程序。");
        if (release.Sequence <= _snapshots.Current.Sequence && release.SnapshotId != _snapshots.Current.SnapshotId) throw new InvalidDataException("离线包版本早于当前资源，请使用本地回退功能。");
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "update.json" };
        foreach (var package in release.Packages)
        {
            var name = "packages/" + package.Id + "-" + package.Version + ".zip";
            expected.Add(name);
            if (!entries.TryGetValue(name, out var packageEntry) || packageEntry.Length != package.Size) throw new InvalidDataException("离线资源包不完整或文件大小不符。");
        }
        if (entries.Keys.Any(p => !expected.Contains(p))) throw new InvalidDataException("离线资源包包含清单之外的文件。");
        // A complete offline set must validate in full, even when identical payloads can be reused locally.
        long verified = 0;
        var offlineTotal = release.Packages.Sum(p => p.Size);
        foreach (var package in release.Packages)
        {
            await using var packageInput = entries["packages/" + package.Id + "-" + package.Version + ".zip"].Open();
            await CopyVerifiedAsync(packageInput, Stream.Null, package.Size, package.Sha256,
                n => progress?.Report(new UpdateProgress("验证离线资源包", verified + n, offlineTotal)), ct).ConfigureAwait(false);
            verified += package.Size;
        }
        await UpdateStorage.WriteAsync(_statePath, _state, ct).ConfigureAwait(false);
        await InstallReleaseAsync(release, entries, progress, ct).ConfigureAwait(false);
        LastCheckResult = MakeResult(catalog);
    }

    private UpdateCheckResult MakeResult(UpdateCatalog catalog)
    {
        var compatible = SelectCompatible(catalog);
        var newer = compatible is not null && compatible.Sequence > _snapshots.Current.Sequence && compatible.SnapshotId != _snapshots.Current.SnapshotId ? compatible : null;
        var app = UpdateSignature.RequireVersion(catalog.App.Version) > UpdateSignature.RequireVersion(_build.AppVersion) ? catalog.App : null;
        var upgradeRequired = compatible is null && catalog.Resources.Any(r => r.Sequence > _snapshots.Current.Sequence);
        return new UpdateCheckResult
        {
            Catalog = catalog, Resource = newer, AppUpdate = app, RequiresAppUpgrade = upgradeRequired, LastChecked = _state.LastAttempt,
            Message = upgradeRequired ? "新地图资源需要新版程序。" : newer is not null ? "发现可安装的地图资源更新。" : app is not null ? "发现程序新版本。" : "当前程序与兼容地图资源已是最新版本。"
        };
    }

    private ResourceRelease? SelectCompatible(UpdateCatalog catalog)
    {
        var appVersion = UpdateSignature.RequireVersion(_build.AppVersion);
        return catalog.Resources.Where(r => r.BaselineId == _build.BaselineId && UpdateSignature.RequireVersion(r.MinAppVersion) <= appVersion &&
                (r.MaxAppVersion is null || appVersion <= UpdateSignature.RequireVersion(r.MaxAppVersion)))
            .OrderByDescending(r => r.Sequence).FirstOrDefault();
    }

    private void AcceptSequence(UpdateCatalog catalog, byte[] envelope)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(JsonSerializer.Deserialize<SignedUpdateEnvelope>(envelope, UpdateJson.Options)!.Payload)));
        if (catalog.Sequence < _state.HighestSequence || (catalog.Sequence == _state.HighestSequence && !string.Equals(hash, _state.HighestPayloadHash, StringComparison.Ordinal)))
            throw new InvalidDataException("拒绝旧清单或同一清单序号下的不同内容。");
        _state.HighestSequence = catalog.Sequence;
        _state.HighestPayloadHash = hash;
    }

    private async Task InstallReleaseAsync(ResourceRelease release, Dictionary<string, ZipArchiveEntry>? offline, IProgress<UpdateProgress>? progress, CancellationToken ct)
    {
        UpdateStorage.RejectLink(_snapshots.Root);
        var needed = new List<ResourcePackage>();
        foreach (var package in release.Packages)
        {
            ct.ThrowIfCancellationRequested();
            var target = PackageDirectory(package);
            if (FindBundled(package) is not null)
            {
                await UpdateStorage.VerifyDirectoryAsync(target, package.Files, ct).ConfigureAwait(false);
            }
            else if (Directory.Exists(target)) await VerifyInstalledAsync(target, package, ct).ConfigureAwait(false);
            else needed.Add(package);
        }
        var plans = offline is null ? await Task.WhenAll(needed.Select(p => BuildPlanAsync(p, ct))).ConfigureAwait(false) : [];
        var requiredBytes = checked(needed.Sum(p => p.Files.Sum(f => f.Size)) + plans.Sum(p => p.DownloadBytes) + 64L * 1024 * 1024);
        if (_freeSpace() < requiredBytes) throw new IOException("磁盘空间不足，无法安全安装资源更新。");
        var work = Path.Combine(_snapshots.Root, "staging", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        long completed = 0;
        var total = offline is not null ? needed.Sum(p => p.Size) : plans.Sum(p => p.DownloadBytes);
        try
        {
            for (var packageIndex = 0; packageIndex < needed.Count; packageIndex++)
            {
                var package = needed[packageIndex];
                ct.ThrowIfCancellationRequested();
                var plan = offline is null ? plans[packageIndex] : null;
                if (plan is not null && plan.UseFiles)
                {
                    progress?.Report(new UpdateProgress($"组装资源（复用 {plan.Reused.Count} 个文件）", completed, total));
                    var unpacked = Path.Combine(work, package.Id);
                    Directory.CreateDirectory(unpacked);
                    foreach (var item in plan.Reused)
                    {
                        var targetFile = UpdateStorage.SafeChild(unpacked, item.File.Path);
                        Directory.CreateDirectory(Path.GetDirectoryName(targetFile)!);
                        await CopyLocalVerifiedAsync(item.SourcePath, targetFile, item.File, ct).ConfigureAwait(false);
                    }
                    foreach (var item in plan.Downloads)
                    {
                        using var response = await GetResponseAsync(new Uri(item.Archive.Url), ct).ConfigureAwait(false);
                        if (response.Content.Headers.ContentLength is long actualLength && actualLength != item.Archive.Size) throw new InvalidDataException("资源文件附件长度与清单不符。");
                        await using var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                        var archivePath = Path.Combine(work, Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(package.Id + item.File.Path))) + ".zip");
                        await using (var output = new FileStream(archivePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous))
                            await CopyVerifiedAsync(source, output, item.Archive.Size, item.Archive.Sha256, n => progress?.Report(new UpdateProgress("下载资源文件", completed + n, total)), ct).ConfigureAwait(false);
                        completed += item.Archive.Size;
                        await ExtractSingleFileAsync(archivePath, unpacked, item.File, ct).ConfigureAwait(false);
                    }
                    await UpdateStorage.VerifyDirectoryAsync(unpacked, package.Files, ct).ConfigureAwait(false);
                    await CommitPackageAsync(unpacked, package, ct).ConfigureAwait(false);
                }
                else
                {
                    var zipPath = Path.Combine(work, package.Id + ".zip");
                    await using (var output = new FileStream(zipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous))
                    {
                        if (offline is not null) { await using var source = offline["packages/" + package.Id + "-" + package.Version + ".zip"].Open(); await CopyVerifiedAsync(source, output, package.Size, package.Sha256, n => progress?.Report(new UpdateProgress("导入资源", completed + n, total)), ct).ConfigureAwait(false); }
                        else { using var response = await GetResponseAsync(new Uri(package.Url), ct).ConfigureAwait(false); if (response.Content.Headers.ContentLength is long actualLength && actualLength != package.Size) throw new InvalidDataException("下载文件长度与发布清单不符。"); await using var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false); await CopyVerifiedAsync(source, output, package.Size, package.Sha256, n => progress?.Report(new UpdateProgress("下载资源", completed + n, total)), ct).ConfigureAwait(false); }
                    }
                    completed += package.Size;
                    progress?.Report(new UpdateProgress("验证并解压资源", completed, total));
                    var unpacked = Path.Combine(work, package.Id); await ExtractPackageAsync(zipPath, unpacked, package, ct).ConfigureAwait(false); await CommitPackageAsync(unpacked, package, ct).ConfigureAwait(false);
                }
            }
            ct.ThrowIfCancellationRequested();
            var packages = release.Packages.Select(p => new SnapshotPackage
            {
                Id = p.Id, Version = p.Version, Kind = p.Kind, Directory = PackageDirectory(p), Sha256 = p.Sha256, Files = p.Files
            }).ToList();
            var candidate = new ResourceSnapshot
            {
                FormatVersion = 2, MinAppVersion = release.MinAppVersion, MaxAppVersion = release.MaxAppVersion,
                SnapshotId = release.SnapshotId, Sequence = release.Sequence, BaselineId = release.BaselineId,
                BaselineRoot = _snapshots.Current.BaselineRoot, MapDataRoot = packages.Single(p => p.Kind == "map-data").Directory, Packages = packages
            };
            progress?.Report(new UpdateProgress("检查资源兼容性", total, total));
            await _snapshots.StageAsync(candidate, ct).ConfigureAwait(false);
            progress?.Report(new UpdateProgress("安装完成，重启软件后生效", total, total));
        }
        finally
        {
            // Delete only this transaction's generated scratch files. Installed packages are immutable and retained.
            try { if (Directory.Exists(work)) { UpdateStorage.RejectLink(work); Directory.Delete(work, true); } }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private sealed record ReusedFile(ResourceFile File, string SourcePath);
    private sealed record DownloadFile(ResourceFile File, ResourceFileArchive Archive);
    private sealed record PackagePlan(bool UseFiles, List<ReusedFile> Reused, List<DownloadFile> Downloads, long DownloadBytes);

    private async Task<PackagePlan> BuildPlanAsync(ResourcePackage package, CancellationToken ct)
    {
        if (package.FileArchives is null) return new(false, [], [], package.Size);
        var sources = CandidateDirectories(package);
        var reused = new List<ReusedFile>(); var downloads = new List<DownloadFile>();
        var archives = package.FileArchives.ToDictionary(a => a.Path, StringComparer.OrdinalIgnoreCase);
        foreach (var file in package.Files)
        {
            string? found = null;
            foreach (var directory in sources)
            {
                var path = UpdateStorage.SafeChild(directory, file.Path);
                try { await UpdateStorage.VerifyFileAsync(path, file, ct).ConfigureAwait(false); found = path; break; }
                catch (InvalidDataException) { }
                catch (IOException) { }
            }
            if (found is not null) reused.Add(new(file, found)); else downloads.Add(new(file, archives[file.Path]));
        }
        var bytes = downloads.Sum(d => d.Archive.Size);
        return new(bytes < package.Size, reused, downloads, bytes);
    }

    private IEnumerable<string> CandidateDirectories(ResourcePackage package)
    {
        foreach (var p in _snapshots.Current.Packages.Where(p => p.Id == package.Id && p.Kind == package.Kind)) yield return p.Directory;
        var bundled = _snapshots.Bundled.Packages.Where(p => p.Id == package.Id && p.Kind == package.Kind).Select(p => p.Directory);
        foreach (var path in bundled) yield return path;
        var root = Path.Combine(_snapshots.Root, "packages", package.Id);
        if (Directory.Exists(root)) foreach (var path in Directory.EnumerateDirectories(root)) yield return path;
    }

    private async Task CommitPackageAsync(string unpacked, ResourcePackage package, CancellationToken ct)
    {
        var target = PackageDirectory(package); Directory.CreateDirectory(Path.GetDirectoryName(target)!); UpdateStorage.RejectLink(Path.GetDirectoryName(target)!); ct.ThrowIfCancellationRequested();
        await UpdateStorage.WriteAsync(target + ".receipt.json", package, ct).ConfigureAwait(false); await UpdateStorage.MoveDirectoryAsync(unpacked, target, ct).ConfigureAwait(false);
    }

    private static async Task CopyLocalVerifiedAsync(string sourcePath, string targetPath, ResourceFile file, CancellationToken ct)
    {
        await using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var target = new FileStream(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous);
        await CopyVerifiedAsync(source, target, file.Size, file.Sha256, null, ct).ConfigureAwait(false);
    }

    private static async Task ExtractSingleFileAsync(string archivePath, string directory, ResourceFile file, CancellationToken ct)
    {
        using var archive = ZipFile.OpenRead(archivePath); var entries = ReadArchiveEntries(archive);
        if (entries.Count != 1 || !entries.TryGetValue(file.Path, out var entry) || entry.Length != file.Size) throw new InvalidDataException("资源文件附件内容与清单不符。");
        var target = UpdateStorage.SafeChild(directory, file.Path); Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        await using var source = entry.Open(); await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous);
        await CopyVerifiedAsync(source, output, file.Size, file.Sha256, null, ct).ConfigureAwait(false);
    }

    private SnapshotPackage? FindBundled(ResourcePackage package) => _snapshots.FindBundledPackage(new SnapshotPackage { Id = package.Id, Version = package.Version, Kind = package.Kind, Sha256 = package.Sha256, Files = package.Files });

    private string PackageDirectory(ResourcePackage package) => FindBundled(package)?.Directory ?? Path.Combine(_snapshots.Root, "packages", package.Id, package.Version);

    private static async Task VerifyInstalledAsync(string directory, ResourcePackage package, CancellationToken ct)
    {
        UpdateStorage.RejectLink(directory);
        var manifestPath = directory + ".receipt.json";
        if (!File.Exists(manifestPath))
        {
            // Recover only a complete payload that exactly matches the newly verified signed descriptor.
            await UpdateStorage.VerifyDirectoryAsync(directory, package.Files, ct).ConfigureAwait(false);
            await UpdateStorage.WriteAsync(manifestPath, package, ct).ConfigureAwait(false);
        }
        var existing = UpdateStorage.Read<ResourcePackage>(manifestPath);
        if (existing.Id != package.Id || existing.Version != package.Version || existing.Kind != package.Kind || existing.Size != package.Size || !existing.Sha256.Equals(package.Sha256, StringComparison.OrdinalIgnoreCase) ||
            !JsonSerializer.SerializeToUtf8Bytes(existing.Files, UpdateJson.Options).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(package.Files, UpdateJson.Options)))
            throw new InvalidDataException("同一资源包版本已存在不同内容，请由维护者发布新版本。");
        await UpdateStorage.VerifyDirectoryAsync(directory, package.Files, ct).ConfigureAwait(false);
    }

    private static async Task ExtractPackageAsync(string zipPath, string directory, ResourcePackage package, CancellationToken ct)
    {
        using var zip = ZipFile.OpenRead(zipPath);
        var entries = ReadArchiveEntries(zip);
        if (entries.Count != package.Files.Count) throw new InvalidDataException("资源包文件数与清单不一致。");
        Directory.CreateDirectory(directory);
        foreach (var file in package.Files)
        {
            ct.ThrowIfCancellationRequested();
            if (!entries.TryGetValue(file.Path, out var entry) || entry.Length != file.Size) throw new InvalidDataException("资源包缺少文件或展开长度不符。");
            var path = UpdateStorage.SafeChild(directory, file.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await using var source = entry.Open();
            await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous);
            await CopyVerifiedAsync(source, output, file.Size, file.Sha256, null, ct).ConfigureAwait(false);
        }
    }

    private static Dictionary<string, ZipArchiveEntry> ReadArchiveEntries(ZipArchive zip)
    {
        if (zip.Entries.Count > 100001) throw new InvalidDataException("资源压缩包条目过多。");
        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        var allNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in zip.Entries)
        {
            var isDirectory = entry.FullName.EndsWith('/');
            var name = isDirectory ? entry.FullName[..^1] : entry.FullName;
            UpdateStorage.ValidateRelativePath(name);
            if (!allNames.Add(name)) throw new InvalidDataException("资源压缩包包含重复路径。");
            var unixType = (entry.ExternalAttributes >> 16) & 0xF000;
            if (unixType != 0 && unixType != 0x8000 && unixType != 0x4000 || (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("资源压缩包不能包含链接或特殊文件。");
            if (isDirectory)
            {
                if (entry.Length != 0) throw new InvalidDataException("资源压缩包目录条目无效。");
                continue;
            }
            if (unixType == 0x4000) throw new InvalidDataException("资源压缩包目录类型无效。");
            entries.Add(name, entry);
        }
        return entries;
    }

    private async Task<byte[]> DownloadManifestAsync(CancellationToken ct)
    {
        using var response = await GetResponseAsync(StableUri, ct).ConfigureAwait(false);
        if (response.Content.Headers.ContentLength > UpdateSignature.MaxManifestBytes) throw new InvalidDataException("更新清单过大。");
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        return await ReadBoundedAsync(stream, UpdateSignature.MaxManifestBytes, ct).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> GetResponseAsync(Uri uri, CancellationToken ct)
    {
        for (var redirects = 0; redirects < 6; redirects++)
        {
            UpdateSignature.ValidateResponseUri(uri);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd("WWMAP-TOOLS/" + _build.AppVersion);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            HttpResponseMessage response;
            try { response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException ex) when (!ct.IsCancellationRequested) { throw new TimeoutException("连接或等待下载响应超时，请重试。", ex); }
            try
            {
                UpdateSignature.ValidateResponseUri(response.RequestMessage?.RequestUri);
                if (response.StatusCode is HttpStatusCode.MovedPermanently or HttpStatusCode.Redirect or HttpStatusCode.RedirectMethod or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
                {
                    var location = response.Headers.Location ?? throw new InvalidDataException("下载重定向缺少地址。");
                    uri = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    response.Dispose();
                    continue;
                }
                response.EnsureSuccessStatusCode();
                return response;
            }
            catch { response.Dispose(); throw; }
        }
        throw new InvalidDataException("下载重定向次数过多。");
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream input, int limit, CancellationToken ct)
    {
        using var output = new MemoryStream();
        var buffer = new byte[65536];
        while (true)
        {
            var count = await ReadWithTimeoutAsync(input, buffer, ct).ConfigureAwait(false);
            if (count == 0) break;
            if (output.Length + count > limit) throw new InvalidDataException("更新清单超过大小限制。");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    private static async Task CopyVerifiedAsync(Stream input, Stream output, long length, string hash, Action<long>? progress, CancellationToken ct)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[131072];
        long copied = 0;
        while (true)
        {
            var count = await ReadWithTimeoutAsync(input, buffer, ct).ConfigureAwait(false);
            if (count == 0) break;
            copied = checked(copied + count);
            if (copied > length) throw new InvalidDataException("资源流长度超过清单限制。");
            digest.AppendData(buffer, 0, count);
            await output.WriteAsync(buffer.AsMemory(0, count), ct).ConfigureAwait(false);
            progress?.Invoke(copied);
        }
        if (copied != length || !Convert.ToHexString(digest.GetHashAndReset()).Equals(hash, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("资源文件下载不完整或哈希校验失败。");
    }

    private static async ValueTask<int> ReadWithTimeoutAsync(Stream input, byte[] buffer, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        try { return await input.ReadAsync(buffer.AsMemory(), timeout.Token).ConfigureAwait(false); }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested) { throw new TimeoutException("资源传输长时间没有响应，请重试。", ex); }
    }

    public void Dispose() { if (_ownsHttp) _http.Dispose(); }

    private void EnsureAvailable()
    {
        if (!string.IsNullOrEmpty(_initializationError)) throw new InvalidOperationException(_initializationError);
    }

    private UpdaterState LoadState()
    {
        try
        {
            var state = UpdateStorage.Read<UpdaterState>(_statePath);
            if (state.HighestSequence < 0 || (state.HighestSequence > 0 && !UpdateSignature.IsHash(state.HighestPayloadHash))) throw new InvalidDataException("清单序号状态无效。");
            return state;
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            throw new InvalidDataException("更新状态无法读取，已停用在线更新以保留清单防回退记录。请保留 update-state.json 并联系维护者修复。", ex);
        }
    }

    private sealed class UpdaterState
    {
        public bool AutoCheckEnabled { get; set; } = true;
        public DateTimeOffset? LastAttempt { get; set; }
        public long HighestSequence { get; set; }
        public string HighestPayloadHash { get; set; } = "";
        public string LastError { get; set; } = "";
    }
}
