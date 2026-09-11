[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputRoot)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ResourceUpdateCatalog.ps1')
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
if(Test-Path -LiteralPath $OutputRoot){throw 'Use a fresh catalog regression output directory.'}
[IO.Directory]::CreateDirectory($OutputRoot)|Out-Null
$passed=[Collections.Generic.List[string]]::new()
$old=@{schemaVersion=1;sequence=1;app=@{version='2026.9.9.1';url='https://github.com/kahvia-d/WWMAP-TOOLS/releases/tag/fixture1'};resources=@(@{snapshotId='fixture1';sequence=1;baselineId='baseline1';minAppVersion='2026.9.9.1';packages=@(@{id='map-data';version='2026.9.9.1';kind='map-data';size=100;sha256=('a'*64);url='https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/fixture1/map-data.zip';files=@(@{path='points.json';size=10;sha256=('b'*64)})})})}
function Copy-Catalog($Catalog){return ($Catalog|ConvertTo-Json -Depth 20|ConvertFrom-Json)}
function Expect-Rejection([string]$Name,[scriptblock]$Change){
    $candidate=Copy-Catalog $old;$candidate.sequence=2
    & $Change $candidate
    try { Assert-ResourceCatalogTransition $old $candidate }
    catch { $passed.Add($Name); return }
    throw "Expected rejection: $Name"
}
$same=Copy-Catalog $old;$same.sequence=2;$same.resources[0].packages[0].url='https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/fixture2/map-data.zip'
Assert-ResourceCatalogTransition $old $same
$passed.Add('same immutable bytes with different release URL accepted')
Expect-Rejection 'same package version with changed archive hash rejected' {param($c)$c.resources[0].packages[0].sha256='c'*64}
Expect-Rejection 'same package version with changed archive size rejected' {param($c)$c.resources[0].packages[0].size=101}
Expect-Rejection 'same package version with changed kind rejected' {param($c)$c.resources[0].packages[0].kind='candidate'}
Expect-Rejection 'same package version with changed file hash rejected' {param($c)$c.resources[0].packages[0].files[0].sha256='c'*64}
Expect-Rejection 'same package version with changed file size rejected' {param($c)$c.resources[0].packages[0].files[0].size=11}
Expect-Rejection 'same package version with changed file path rejected' {param($c)$c.resources[0].packages[0].files[0].path='other.json'}
Expect-Rejection 'same package version with missing file rejected' {param($c)$c.resources[0].packages[0].files=@()}
$withFileArchive = Copy-Catalog $old
$withFileArchive.resources[0].packages[0] | Add-Member -NotePropertyName fileArchives -NotePropertyValue @(@{path='points.json';size=30;sha256=('e'*64);url='https://github.com/kahvia-d/WWMAP-TOOLS/releases/download/fixture1/file-e.zip'})
$archiveMutation = Copy-Catalog $withFileArchive; $archiveMutation.sequence = 2; $archiveMutation.resources[0].packages[0].fileArchives[0].sha256 = 'f'*64
try { Assert-ResourceCatalogTransition $withFileArchive $archiveMutation; throw 'Expected rejection: same package version with changed file archive rejected' } catch { if ($_.Exception.Message -like 'Expected rejection:*') { throw }; $passed.Add('same package version with changed file archive rejected') }
Expect-Rejection 'case and numeric version aliases cannot bypass immutability' {param($c)$c.resources[0].packages[0].id='MAP-DATA';$c.resources[0].packages[0].version='2026.09.09.01';$c.resources[0].packages[0].sha256='c'*64}
Expect-Rejection 'existing baseline cannot be silently dropped' {param($c)$c.resources[0].baselineId='baseline2'}
Expect-Rejection 'program downgrade caused by missing previous catalog rejected' {param($c)$c.app.version='2026.9.8.1'}
Expect-Rejection 'conflicting shared identity across baselines rejected' {param($c)
    $other=Copy-Catalog $c.resources[0];$other.baselineId='baseline2';$other.snapshotId='fixture2'
    $other.packages[0].sha256='c'*64;$c.resources+=@($other)
}
$new=Copy-Catalog $old;$new.sequence=2;$new.resources[0].packages[0].version='2026.9.9.2';$new.resources[0].packages[0].sha256='c'*64
Assert-ResourceCatalogTransition $old $new
$passed.Add('changed bytes with new package version accepted')
# Round-trip actual P-256 signed fixture payloads so comparison is independent of serialized property order.
$key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
function Read-SignedFixture($Catalog,[string]$Name){
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Catalog|ConvertTo-Json -Depth 20))
    $signature=$key.SignData($bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
    $envelope=@{keyId='isolated-catalog-fixture';payload=[Convert]::ToBase64String($bytes);signature=[Convert]::ToBase64String($signature)}
    [IO.File]::WriteAllText((Join-Path $OutputRoot "$Name.json"),($envelope|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    if(-not $key.VerifyData($bytes,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)){throw 'Fixture signature verification failed'}
    return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($envelope.payload))|ConvertFrom-Json)
}
try {
    $verifiedOld=Read-SignedFixture $old 'previous-signed'
    $verifiedNew=Read-SignedFixture $new 'next-signed'
    Assert-ResourceCatalogTransition $verifiedOld $verifiedNew
    $passed.Add('verified signed catalog payload transition accepted')
}finally{$key.Dispose()}
$withProgram = Copy-Catalog $old
$programPackage = @{sha256=('d'*64);size=200;sourceCommit=('a'*40);launcherProtocol=1;files=@(@{path='app.exe';size=10;sha256=('b'*64)})}
$withProgram.app | Add-Member -NotePropertyName package -NotePropertyValue $programPackage
$retained = Copy-Catalog $withProgram; $retained.sequence = 2
Assert-ResourceCatalogTransition $withProgram $retained
$passed.Add('resource-only release retains signed program package')
foreach ($property in @('sha256','size','sourceCommit','launcherProtocol','files','removed')) {
    $changed = Copy-Catalog $retained
    switch ($property) {
        'sha256' { $changed.app.package.sha256 = 'e'*64 }
        'size' { $changed.app.package.size = 201 }
        'sourceCommit' { $changed.app.package.sourceCommit = 'c'*40 }
        'launcherProtocol' { $changed.app.package.launcherProtocol = 2 }
        'files' { $changed.app.package.files[0].sha256 = 'e'*64 }
        'removed' { $changed.app.package = $null }
    }
    $rejected = $false
    try { Assert-ResourceCatalogTransition $withProgram $changed } catch { $rejected = $true }
    if (-not $rejected) { throw "Program package mutation was accepted: $property" }
    $passed.Add("immutable signed program rejects $property mutation")
}
[IO.File]::WriteAllText((Join-Path $OutputRoot 'test-report.json'),(@{passed=$passed.Count;tests=@($passed.ToArray())}|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Write-Host "PASS $($passed.Count) catalog transition checks."
