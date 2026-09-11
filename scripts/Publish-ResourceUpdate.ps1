# Requires PowerShell 7 and authenticated GitHub CLI. This script is the sole remote mutation entrypoint.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PreparedRoot,
    [Parameter(Mandatory)][string]$NotesFile,
    [string]$Dotnet,
    [string]$PublicKey,
    [string]$PublisherDll,
    [string]$ProgramZip
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'PowerShell 7 or newer is required.' }
$sourceRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'ResourceUpdateCatalog.ps1')
if (-not $Dotnet) { $Dotnet = Join-Path $sourceRoot 'tools/dotnet-sdk-8.0.424/dotnet.exe' }
if (-not $PublicKey) { $PublicKey = Join-Path $sourceRoot 'Assets/Updates/trusted-keys.json' }
if (-not $PublisherDll) { $PublisherDll = Join-Path $sourceRoot 'tools/UpdatePublisher/bin/Release/net8.0/UpdatePublisher.dll' }
$PreparedRoot = [IO.Path]::GetFullPath($PreparedRoot)
$repo = 'kahvia-d/WWMAP-TOOLS'
$report = Get-Content -LiteralPath (Join-Path $PreparedRoot 'release-report.json') -Raw | ConvertFrom-Json
if (-not $report.production -or -not $report.nativePassed) { throw 'Only production-signed, native-verified artifacts may be published.' }
if ($report.sourceDirty -ne $false -or $report.sourceTreeSha256 -notmatch '^[a-f0-9]{64}$') { throw 'A working-tree QA build cannot be published. Commit the reviewed source and rebuild from that exact clean commit.' }
$manifest = Join-Path $PreparedRoot 'update.json'
if ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne $report.signedManifestSha256) { throw 'Manifest differs from reviewed release report.' }
& $Dotnet $PublisherDll verify --input $PreparedRoot --public-key $PublicKey --snapshot-id $report.snapshotId
if ($LASTEXITCODE -ne 0) { throw 'Prepared artifacts failed verification.' }
function Invoke-Gh([string[]]$Arguments) {
    $result = & gh @Arguments
    if ($LASTEXITCODE -ne 0) { throw ('GitHub operation failed: gh ' + ($Arguments -join ' ') + '; stable channel has not been advanced by this failed operation.') }
    return $result
}
$tag = [string]$report.tag
$envelope = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
$catalog = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envelope.payload)) | ConvertFrom-Json
if ($catalog.app.url -eq "https://github.com/$repo/releases/tag/$tag" -and -not $ProgramZip) { throw 'A program release needs -ProgramZip with its verified archive report.' }
$assets = [Collections.Generic.List[object]]::new()
foreach ($asset in $report.assets) {
    # Unchanged packages keep their old release URL; do not upload them into a new tag.
    if (([Uri]$asset.url).AbsolutePath -notlike "/$repo/releases/download/$tag/*") { continue }
    $assets.Add([pscustomobject]@{path=(Join-Path $PreparedRoot "packages/$($asset.name)");name=$asset.name;sha256=$asset.sha256})
}
foreach ($asset in @($report.fileAssets)) {
    # Content-addressed file archives may be referenced by a previous release.
    if (([Uri]$asset.url).AbsolutePath -notlike "/$repo/releases/download/$tag/*") { continue }
    $assets.Add([pscustomobject]@{path=(Join-Path $PreparedRoot "files/$($asset.name)");name=$asset.name;sha256=$asset.sha256})
}
$assets.Add([pscustomobject]@{path=$manifest;name='update.json';sha256=$report.signedManifestSha256})
$assets.Add([pscustomobject]@{path=(Join-Path $PreparedRoot $report.offline.name);name=$report.offline.name;sha256=$report.offline.sha256})
if ($ProgramZip) {
    $programReport = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($ProgramZip, '.report.json')) -Raw | ConvertFrom-Json
    if (-not $programReport.passed -or $programReport.sourceDirty -ne $false -or $programReport.sourceCommit -ne $report.sourceCommit -or $programReport.version -ne $report.appVersion) { throw 'Program archive lacks a matching clean-source package validation report.' }
    if ((Get-FileHash -LiteralPath $ProgramZip -Algorithm SHA256).Hash -ne $programReport.sha256) { throw 'Program archive changed after verification.' }
    if ([version]$programReport.version -ge [version]'2026.9.9.4' -and (-not $catalog.app.package -or
        $catalog.app.package.sha256 -ne $programReport.sha256 -or $catalog.app.package.size -ne (Get-Item -LiteralPath $ProgramZip).Length -or
        $catalog.app.package.sourceCommit -ne $programReport.sourceCommit -or
        $catalog.app.package.url -ne "https://github.com/$repo/releases/download/$tag/$([IO.Path]::GetFileName($ProgramZip))")) {
        throw 'Program archive is not bound to this release by the signed update catalog.'
    }
    $assets.Add([pscustomobject]@{path=[IO.Path]::GetFullPath($ProgramZip);name=[IO.Path]::GetFileName($ProgramZip);sha256=$programReport.sha256})
}
foreach ($asset in $assets) {
    if ((Get-Item -LiteralPath $asset.path).Length -ge 2GB) { throw "GitHub release attachments must be smaller than 2 GiB: $($asset.name)" }
    if ((Get-FileHash -LiteralPath $asset.path -Algorithm SHA256).Hash -ne $asset.sha256) { throw "Asset changed after preparation: $($asset.name)" }
}
# Read stable before creating a release, and use its blob SHA as a compare-and-swap on promotion.
$stableOutput = & gh api "repos/$repo/contents/updates/stable.json?ref=main" 2>$null
$stableSha = $null
$verification = Join-Path $PreparedRoot ('publish-verification-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($verification) | Out-Null
if ($LASTEXITCODE -eq 0) {
    $old = $stableOutput | ConvertFrom-Json
    $stableSha = $old.sha
    $oldFile = Join-Path $verification 'previous-stable.json'
    [IO.File]::WriteAllBytes($oldFile, [Convert]::FromBase64String(($old.content -replace '\s','')))
    $oldCheck = & $Dotnet $PublisherDll verify-manifest --input $oldFile --public-key $PublicKey
    if ($LASTEXITCODE -ne 0) { throw 'Current stable signature could not be verified.' }
    $oldSequence = ($oldCheck | ConvertFrom-Json).sequence
    if ($oldSequence -gt $report.sequence) { throw 'Refusing to replace a newer stable channel.' }
    if ($oldSequence -eq $report.sequence) {
        if ((Get-FileHash -LiteralPath $oldFile -Algorithm SHA256).Hash -eq $report.signedManifestSha256) { Write-Host 'This exact update is already stable.'; exit 0 }
        throw 'Stable sequence already exists with different bytes.'
    }
    $oldEnvelope = Get-Content -LiteralPath $oldFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $oldCatalog = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($oldEnvelope.payload)) | ConvertFrom-Json
    # Compare with the actual verified stable feed before creating/uploading/publishing anything.
    # URLs may change for identical bytes; package identity and its full inventory may not.
    Assert-ResourceCatalogTransition $oldCatalog $catalog
} else {
    # Distinguish an absent file from authentication/network errors by checking the parent branch.
    $tree = (Invoke-Gh @('api',"repos/$repo/git/trees/main?recursive=1")) | ConvertFrom-Json
    if ($tree.truncated -or @($tree.tree | Where-Object path -EQ 'updates/stable.json').Count) { throw 'Unable to safely determine current stable channel.' }
}
$releaseOutput = & gh api "repos/$repo/releases/tags/$tag" 2>$null
if ($LASTEXITCODE -ne 0) {
    # Drafts without a created Git tag can be absent from the by-tag endpoint.
    # Discover and reuse them by ID instead of creating another draft on retry.
    $all = (Invoke-Gh @('api',"repos/$repo/releases?per_page=100")) | ConvertFrom-Json
    $matching = @($all | Where-Object tag_name -EQ $tag)
    if ($matching.Count -eq 0) {
        Invoke-Gh @('release','create',$tag,'--repo',$repo,'--target',[string]$report.sourceCommit,'--draft','--title',$tag,'--notes-file',[IO.Path]::GetFullPath($NotesFile)) | Out-Null
        $all = (Invoke-Gh @('api',"repos/$repo/releases?per_page=100")) | ConvertFrom-Json
        $matching = @($all | Where-Object tag_name -EQ $tag)
    }
    if ($matching.Count -ne 1) { throw 'Cannot uniquely identify the release draft. No attachments were changed.' }
    $release = $matching[0]
} else {
    $release = $releaseOutput | ConvertFrom-Json
}
$release = (Invoke-Gh @('api',"repos/$repo/releases/$($release.id)")) | ConvertFrom-Json
if ($release.tag_name -ne $tag) { throw 'Release identity changed during lookup.' }
$tagCommit = [string](& gh api "repos/$repo/commits/$tag" --jq '.sha' 2>$null)
if ($LASTEXITCODE -eq 0) {
    if ($tagCommit.Trim() -ne $report.sourceCommit) { throw 'Release tag does not reference the reviewed source commit.' }
} elseif (-not $release.draft -or $release.target_commitish -ne $report.sourceCommit) {
    throw 'Cannot verify the reviewed source commit or pending draft tag target.'
}
foreach ($asset in $assets) {
    $existing = @($release.assets | Where-Object name -EQ $asset.name)
    if ($existing.Count) {
        $checkRoot = Join-Path $verification ('existing-' + [guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($checkRoot) | Out-Null
        Invoke-Gh @('release','download',$tag,'--repo',$repo,'--pattern',$asset.name,'--dir',$checkRoot) | Out-Null
        if ((Get-FileHash -LiteralPath (Join-Path $checkRoot $asset.name) -Algorithm SHA256).Hash -ne $asset.sha256) { throw "Remote asset already exists with different bytes: $($asset.name). Nothing was overwritten." }
    } else {
        if (-not $release.draft) { throw "Published release is missing an expected asset: $($asset.name). Do not modify an immutable release." }
        Invoke-Gh @('release','upload',$tag,$asset.path,'--repo',$repo) | Out-Null
    }
}
# Verify all remote draft bytes, including files uploaded in this invocation.
foreach ($asset in $assets) {
    $dir = Join-Path $verification ('uploaded-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($dir) | Out-Null
    Invoke-Gh @('release','download',$tag,'--repo',$repo,'--pattern',$asset.name,'--dir',$dir) | Out-Null
    if ((Get-FileHash -LiteralPath (Join-Path $dir $asset.name) -Algorithm SHA256).Hash -ne $asset.sha256) { throw "Uploaded bytes failed verification: $($asset.name)" }
}
if ($release.draft) { Invoke-Gh @('release','edit',$tag,'--repo',$repo,'--draft=false','--latest=false') | Out-Null }
$publishedCommit = [string](Invoke-Gh @('api',"repos/$repo/commits/$tag",'--jq','.sha'))
if ($publishedCommit.Trim() -ne $report.sourceCommit) { throw 'Published tag does not match the reviewed source commit. Stable channel remains unchanged.' }
# Use unauthenticated public downloads and separate connection/transfer timeouts. Never print redirected signed URLs.
$handler = [Net.Http.SocketsHttpHandler]::new(); $handler.ConnectTimeout = [TimeSpan]::FromSeconds(20)
$client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromHours(2)
try {
    $publicChecks = @($assets | ForEach-Object { [pscustomobject]@{name=$_.name;sha256=$_.sha256;url="https://github.com/$repo/releases/download/$tag/$([Uri]::EscapeDataString($_.name))"} })
    $publicChecks += @($report.assets | Where-Object { ([Uri]$_.url).AbsolutePath -notlike "/$repo/releases/download/$tag/*" })
    foreach ($asset in $publicChecks) {
        $url = [string]$asset.url
        $response = $client.GetAsync($url,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            $response.EnsureSuccessStatusCode() | Out-Null
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $transfer = [Threading.CancellationTokenSource]::new([TimeSpan]::FromHours(2))
            try { $sha = [Security.Cryptography.SHA256]::HashDataAsync($stream,$transfer.Token).GetAwaiter().GetResult(); $actual = [Convert]::ToHexString($sha) }
            finally { $transfer.Dispose(); $stream.Dispose() }
            if ($actual -ne $asset.sha256) { throw "Public asset verification failed: $($asset.name)" }
        } finally { $response.Dispose() }
    }
} finally { $client.Dispose(); $handler.Dispose() }
$promotion = [ordered]@{message="Publish verified resource update $($report.snapshotId)";branch='main';content=[Convert]::ToBase64String([IO.File]::ReadAllBytes($manifest))}
if ($stableSha) { $promotion.sha = $stableSha }
$promotionFile = Join-Path $verification 'stable-promotion.json'
[IO.File]::WriteAllText($promotionFile,($promotion | ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Invoke-Gh @('api',"repos/$repo/contents/updates/stable.json",'--method','PUT','--input',$promotionFile) | Out-Null
$after = (Invoke-Gh @('api',"repos/$repo/contents/updates/stable.json?ref=main")) | ConvertFrom-Json
$remoteBytes = [Convert]::FromBase64String(($after.content -replace '\s',''))
if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($remoteBytes)) -ne $report.signedManifestSha256) { throw 'Stable channel verification failed after promotion.' }
Write-Host "Verified release https://github.com/$repo/releases/tag/$tag and promoted stable sequence $($report.sequence)."
