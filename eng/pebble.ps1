# Builds Pebble (Let's Encrypt's ACME test server) into .pebble/ for the integration tests. Needs Git and Go.
$ErrorActionPreference = 'Stop'
$version = if ($env:PEBBLE_VERSION) { $env:PEBBLE_VERSION } else { 'v2.10.1' }
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root '.pebble'
$exe = if ($IsWindows -or $env:OS -eq 'Windows_NT') { '.exe' } else { '' }

if ((Test-Path (Join-Path $dest "bin/pebble$exe")) -and ((Get-Content (Join-Path $dest 'VERSION') -ErrorAction SilentlyContinue) -eq $version)) {
    Write-Host "Pebble $version already built in $dest"
    exit 0
}

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
git clone --quiet --depth 1 --branch $version https://github.com/letsencrypt/pebble.git (Join-Path $dest 'src')
if ($LASTEXITCODE -ne 0) { throw 'git clone failed' }

Push-Location (Join-Path $dest 'src')
try {
    # The trailing separator tells Go the output is a directory.
    go build -o ((Join-Path $dest 'bin') + [IO.Path]::DirectorySeparatorChar) ./cmd/pebble ./cmd/pebble-challtestsrv
    if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
} finally {
    Pop-Location
}
Set-Content (Join-Path $dest 'VERSION') $version
Write-Host "Pebble $version built in $dest"
