#nullable enable
using System.Text.Json;

namespace IMao_WinUI.Core.Updates;

public static class UpdateJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true };
}

public sealed record BuildInfo
{
    public string AppVersion { get; init; } = "2026.9.9.1";
    public string BaselineId { get; init; } = "map-baseline-1";
    public string SourceCommit { get; init; } = "development";
}

public sealed record SignedUpdateEnvelope
{
    public string KeyId { get; init; } = "";
    public string Payload { get; init; } = "";
    public string Signature { get; init; } = "";
}

public sealed record TrustedUpdateKey
{
    public string KeyId { get; init; } = "";
    public string PublicKey { get; init; } = "";
    public bool TestOnly { get; init; }
}

public sealed record TrustedUpdateKeys
{
    public List<TrustedUpdateKey> Keys { get; init; } = new();
}

public sealed record UpdateCatalog
{
    public int SchemaVersion { get; init; } = 1;
    public long Sequence { get; init; }
    public ProgramRelease App { get; init; } = new();
    public List<ResourceRelease> Resources { get; init; } = new();
}

public sealed record ProgramRelease
{
    public string Version { get; init; } = "";
    public string Url { get; init; } = "";
    public string Notes { get; init; } = "";
    public ProgramPackage? Package { get; init; }
}

public sealed record ProgramPackage
{
    public int LauncherProtocol { get; init; } = 1;
    public string Architecture { get; init; } = "win-x64";
    public string SourceCommit { get; init; } = "";
    public string BaselineId { get; init; } = "";
    public string Url { get; init; } = "";
    public long Size { get; init; }
    public string Sha256 { get; init; } = "";
    public List<ResourceFile> Files { get; init; } = new();
}

public sealed record ResourceRelease
{
    public string SnapshotId { get; init; } = "";
    public long Sequence { get; init; }
    public string BaselineId { get; init; } = "";
    public string MinAppVersion { get; init; } = "";
    public string? MaxAppVersion { get; init; }
    public string Notes { get; init; } = "";
    public List<ResourcePackage> Packages { get; init; } = new();
}

public sealed record ResourcePackage
{
    public string Id { get; init; } = "";
    public string Version { get; init; } = "";
    public string Kind { get; init; } = "";
    public string Url { get; init; } = "";
    public long Size { get; init; }
    public string Sha256 { get; init; } = "";
    public List<ResourceFile> Files { get; init; } = new();
    // Optional for compatibility with published schema-v1 catalogs.  Each archive
    // contains exactly the named resource file and is independently signed by the
    // catalog envelope.
    public List<ResourceFileArchive>? FileArchives { get; init; }
}

public sealed record ResourceFile
{
    public string Path { get; init; } = "";
    public long Size { get; init; }
    public string Sha256 { get; init; } = "";
}

public sealed record ResourceFileArchive
{
    public string Path { get; init; } = "";
    public string Url { get; init; } = "";
    public long Size { get; init; }
    public string Sha256 { get; init; } = "";
}

public sealed record SnapshotPackage
{
    public string Id { get; init; } = "";
    public string Version { get; init; } = "";
    public string Kind { get; init; } = "";
    public string Directory { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public List<ResourceFile> Files { get; init; } = new();
}

public sealed record ResourceSnapshot
{
    public int FormatVersion { get; init; } = 1;
    public string SnapshotId { get; init; } = "";
    public long Sequence { get; init; }
    public string BaselineId { get; init; } = "";
    public string MinAppVersion { get; init; } = "";
    public string? MaxAppVersion { get; init; }
    public string BaselineRoot { get; init; } = "";
    public string MapDataRoot { get; init; } = "";
    public bool Bundled { get; init; }
    public List<SnapshotPackage> Packages { get; init; } = new();
}

public sealed record UpdateProgress(string Stage, long Completed, long Total);
