$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputRoot = Join-Path $projectRoot 'output'
$stagingPath = Join-Path (Join-Path $projectRoot 'tmp/packages') ('guanlan-package-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
foreach ($entry in @('server.mjs', 'package.json', 'README.md', '.env.example', '.gitignore', 'Dockerfile', '启动观澜.cmd', 'lib', 'static', 'tests', 'scripts', 'docs', '.github')) {
    $source = Join-Path $projectRoot $entry
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $stagingPath -Recurse }
}
$dataDestination = Join-Path $stagingPath 'data'
New-Item -ItemType Directory -Path $dataDestination -Force | Out-Null
foreach ($entry in @('verified_sources.json', 'asset-example.json', 'sbom-example.json')) {
    Copy-Item -LiteralPath (Join-Path $projectRoot ('data/' + $entry)) -Destination $dataDestination
}
$reportSource = Join-Path $projectRoot 'output/观澜技术报告.pdf'
if (Test-Path -LiteralPath $reportSource) {
    $reportDestination = Join-Path $stagingPath 'output'
    New-Item -ItemType Directory -Path $reportDestination -Force | Out-Null
    Copy-Item -LiteralPath $reportSource -Destination $reportDestination
}
$validationDestination = Join-Path $stagingPath 'artifacts'
New-Item -ItemType Directory -Path $validationDestination -Force | Out-Null
foreach ($entry in @('system-tests.txt', 'evaluation.json', 'evaluation.md', 'workspace-preview.png')) {
    $source = Join-Path $projectRoot ('artifacts/' + $entry)
    if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $validationDestination }
}
$manifest = Get-ChildItem -LiteralPath $stagingPath -Recurse -File | Sort-Object FullName | ForEach-Object {
    [PSCustomObject]@{
        path = $_.FullName.Substring($stagingPath.Length + 1).Replace('\', '/')
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = $_.Length
    }
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $stagingPath 'MANIFEST.json') -Encoding UTF8
$archivePath = Join-Path $outputRoot ('guanlan-sentinel-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.zip')
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::Open($archivePath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $stagingPath -Recurse -File) {
        $entryName = $file.FullName.Substring($stagingPath.Length + 1).Replace('\', '/')
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entryName) | Out-Null
    }
} finally { $archive.Dispose() }
Write-Output $archivePath
