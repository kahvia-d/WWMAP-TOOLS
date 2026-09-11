#nullable enable
using System.Security.Cryptography;
using System.Text.Json;

namespace IMao_WinUI.Core.Updates;

public static class UpdateSignature
{
    public const int MaxManifestBytes = 8 * 1024 * 1024;

    public static UpdateCatalog Verify(ReadOnlySpan<byte> envelopeBytes, IEnumerable<TrustedUpdateKey> keys, bool allowTestKeys = false)
    {
        if (envelopeBytes.Length > MaxManifestBytes) throw new InvalidDataException("更新清单过大。");
        var envelope = JsonSerializer.Deserialize<SignedUpdateEnvelope>(envelopeBytes, UpdateJson.Options) ?? throw new InvalidDataException("更新清单为空。");
        var matches = keys.Where(k => k.KeyId == envelope.KeyId && (!k.TestOnly || allowTestKeys)).ToArray();
        if (matches.Length != 1) throw new InvalidDataException("更新清单的发布密钥不受信任。请先安装正式程序版本。");
        try
        {
            var payload = Convert.FromBase64String(envelope.Payload);
            var signature = Convert.FromBase64String(envelope.Signature);
            using var verifier = ECDsa.Create();
            var publicKey = Convert.FromBase64String(matches[0].PublicKey);
            verifier.ImportSubjectPublicKeyInfo(publicKey, out var read);
            if (read != publicKey.Length || verifier.KeySize != 256 || verifier.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value || signature.Length != 64 ||
                !verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new InvalidDataException("更新清单签名验证失败。");
            var catalog = JsonSerializer.Deserialize<UpdateCatalog>(payload, UpdateJson.Options) ?? throw new InvalidDataException("更新清单内容为空。");
            ValidateCatalog(catalog);
            return catalog;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException)
        {
            throw new InvalidDataException("更新清单或签名格式无效。", ex);
        }
    }

    public static void ValidateCatalog(UpdateCatalog catalog)
    {
        if (catalog.SchemaVersion != 1 || catalog.Sequence < 1 || catalog.Resources is null || catalog.Resources.Count > 1000 || catalog.App is null)
            throw new InvalidDataException("不支持的更新清单格式。");
        RequireVersion(catalog.App.Version);
        ValidateUrl(catalog.App.Url, asset: false);
        if (catalog.App.Package is not null) ProgramPackageValidation.Validate(catalog.App.Package);
        var snapshots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var release in catalog.Resources)
        {
            UpdateStorage.ValidateId(release.SnapshotId);
            UpdateStorage.ValidateId(release.BaselineId);
            if (!snapshots.Add(release.SnapshotId) || release.Sequence < 1 || release.Sequence > catalog.Sequence || release.Packages is null || release.Packages.Count is < 1 or > 256)
                throw new InvalidDataException("资源快照标识、序号或包数量无效。");
            var min = RequireVersion(release.MinAppVersion);
            if (release.MaxAppVersion is not null && RequireVersion(release.MaxAppVersion) < min) throw new InvalidDataException("程序兼容版本范围无效。");
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var package in release.Packages)
            {
                UpdateStorage.ValidateId(package.Id);
                RequireVersion(package.Version);
                if (!ids.Add(package.Id) || package.Kind is not ("map-data" or "tile" or "candidate") || (package.Kind == "map-data") != (package.Id == "map-data"))
                    throw new InvalidDataException("资源包标识重复或类型不受支持。");
                ValidateUrl(package.Url, asset: true);
                if (package.Size <= 0 || package.Size > 64L * 1024 * 1024 * 1024 || !IsHash(package.Sha256) || package.Files is null || package.Files.Count is < 1 or > 100000)
                    throw new InvalidDataException("资源包大小、哈希或文件数无效。");
                var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                long total = 0;
                foreach (var file in package.Files)
                {
                    ValidateResourceFile(file);
                    if (!paths.Add(file.Path)) throw new InvalidDataException("资源包含重复路径。");
                    total = checked(total + file.Size);
                    if (total > 128L * 1024 * 1024 * 1024) throw new InvalidDataException("资源包展开大小过大。");
                }
                if (package.FileArchives is not null)
                {
                    if (package.FileArchives.Count != package.Files.Count) throw new InvalidDataException("资源文件下载描述不完整。");
                    var expected = package.Files.ToDictionary(f => f.Path, StringComparer.OrdinalIgnoreCase);
                    var described = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var archive in package.FileArchives)
                    {
                        UpdateStorage.ValidateRelativePath(archive.Path);
                        ValidateUrl(archive.Url, asset: true);
                        if (!described.Add(archive.Path) || !expected.ContainsKey(archive.Path) || archive.Size <= 0 || archive.Size > 64L * 1024 * 1024 * 1024 || !IsHash(archive.Sha256))
                            throw new InvalidDataException("资源文件下载描述无效。");
                    }
                }
            }
            if (release.Packages.Count(p => p.Kind == "map-data") != 1) throw new InvalidDataException("资源快照必须包含一个完整地图数据包。");
        }
    }

    internal static void ValidateResourceFile(ResourceFile file)
    {
        UpdateStorage.ValidateRelativePath(file.Path);
        if (file.Path.Equals(".package.json", StringComparison.OrdinalIgnoreCase) || file.Size < 0 || file.Size > 64L * 1024 * 1024 * 1024 || !IsHash(file.Sha256))
            throw new InvalidDataException("资源文件元数据无效。");
        var extension = Path.GetExtension(file.Path);
        if (new[] { ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".msi", ".msp", ".scr", ".cpl", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".reg", ".sys" }.Contains(extension, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("地图资源包不能包含可执行文件或脚本。");
    }

    internal static bool IsHash(string value) => value is not null && value.Length == 64 && value.All(char.IsAsciiHexDigit);

    public static Version RequireVersion(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 100 || value.Any(c => !char.IsAsciiDigit(c) && c != '.') || !Version.TryParse(value, out var result) || result.Build < 0 || result.Revision < 0 || value.Split('.').Length != 4)
            throw new InvalidDataException("版本必须是四段数字，例如 2026.9.9.1。");
        return result;
    }

    internal static void ValidateUrl(string value, bool asset)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            uri.Host != "github.com" || !uri.AbsolutePath.StartsWith("/kahvia-d/WWMAP-TOOLS/releases/", StringComparison.Ordinal))
            throw new InvalidDataException("更新地址必须来自本项目的 GitHub Releases。");
        if (asset && !uri.AbsolutePath.StartsWith("/kahvia-d/WWMAP-TOOLS/releases/download/", StringComparison.Ordinal))
            throw new InvalidDataException("资源下载地址必须是本项目的发行附件。");
    }

    internal static void ValidateResponseUri(Uri? uri)
    {
        if (uri is null) return; // Test handlers may omit RequestMessage.
        if (uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort || !string.IsNullOrEmpty(uri.UserInfo)) throw new InvalidDataException("下载重定向地址不安全。");
        if (uri.Host is "release-assets.githubusercontent.com" or "objects.githubusercontent.com") return;
        if (uri.Host == "raw.githubusercontent.com" && uri.AbsolutePath == "/kahvia-d/WWMAP-TOOLS/main/updates/stable.json") return;
        ValidateUrl(uri.AbsoluteUri, asset: true);
    }
}
