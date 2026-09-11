# Called only after both envelopes pass the authoritative client signature validator.
function Test-SameResourcePackageContent($Left, $Right) {
    if ([string]$Left.kind -cne [string]$Right.kind -or [long]$Left.size -ne [long]$Right.size -or
        -not ([string]$Left.sha256).Equals([string]$Right.sha256,[StringComparison]::OrdinalIgnoreCase) -or
        @($Left.files).Count -ne @($Right.files).Count) { return $false }
    $files = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($file in $Left.files) { $files.Add([string]$file.path,$file) }
    foreach ($file in $Right.files) {
        if (-not $files.ContainsKey([string]$file.path)) { return $false }
        $expected = $files[[string]$file.path]
        if ([long]$expected.size -ne [long]$file.size -or -not ([string]$expected.sha256).Equals([string]$file.sha256,[StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    $leftArchives = @($Left.fileArchives)
    $rightArchives = @($Right.fileArchives)
    if ($leftArchives.Count -ne $rightArchives.Count) { return $false }
    $archives = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($archive in $leftArchives) { $archives.Add([string]$archive.path,$archive) }
    foreach ($archive in $rightArchives) {
        if (-not $archives.ContainsKey([string]$archive.path)) { return $false }
        $expectedArchive = $archives[[string]$archive.path]
        if ([long]$expectedArchive.size -ne [long]$archive.size -or -not ([string]$expectedArchive.sha256).Equals([string]$archive.sha256,[StringComparison]::OrdinalIgnoreCase)) { return $false }
    }
    return $true
}

function Get-ResourcePackageIdentities($Catalog) {
    $identities = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($release in $Catalog.resources) {
        foreach ($package in $release.packages) {
            # Numeric version normalization closes case/leading-zero aliases on Windows.
            $identity = [string]$package.id + '/' + ([version]([string]$package.version)).ToString(4)
            if ($identities.ContainsKey($identity)) {
                if (-not (Test-SameResourcePackageContent $identities[$identity] $package)) {
                    throw "Catalog reuses immutable package identity '$identity' with different content."
                }
            } else { $identities.Add($identity,$package) }
        }
    }
    return ,$identities
}

function Assert-ResourceCatalogTransition($Previous, $Next) {
    if ([long]$Next.sequence -le [long]$Previous.sequence) { throw 'Catalog sequence must increase.' }
    if ([version]([string]$Next.app.version) -lt [version]([string]$Previous.app.version)) { throw 'The next stable catalog cannot downgrade the published program version. Prepare with --previous.' }
    if ([version]([string]$Next.app.version) -eq [version]([string]$Previous.app.version) -and $Previous.app.package) {
        if (-not $Next.app.package -or $Next.app.package.sha256 -ne $Previous.app.package.sha256 -or
            $Next.app.package.sourceCommit -ne $Previous.app.package.sourceCommit -or
            $Next.app.package.launcherProtocol -ne $Previous.app.package.launcherProtocol -or
            $Next.app.package.baselineId -ne $Previous.app.package.baselineId -or $Next.app.package.architecture -ne $Previous.app.package.architecture -or
            -not (Test-SameResourcePackageContent $Previous.app.package $Next.app.package)) {
            throw 'An existing program version cannot change or lose its signed package. Increment the program version.'
        }
    }
    $baselines = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($release in $Next.resources) { [void]$baselines.Add([string]$release.baselineId) }
    foreach ($release in $Previous.resources) {
        if (-not $baselines.Contains([string]$release.baselineId)) {
            throw "Existing supported baseline '$($release.baselineId)' is missing. Prepare with --previous instead of dropping its update entry."
        }
    }
    $oldPackages = Get-ResourcePackageIdentities $Previous
    $newPackages = Get-ResourcePackageIdentities $Next
    foreach ($identity in $newPackages.Keys) {
        if ($oldPackages.ContainsKey($identity) -and -not (Test-SameResourcePackageContent $oldPackages[$identity] $newPackages[$identity])) {
            throw "Immutable package '$identity' already exists with different content. Use a new package version and prepare with --previous."
        }
    }
}
