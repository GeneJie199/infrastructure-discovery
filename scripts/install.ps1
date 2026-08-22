[CmdletBinding()]
param(
    [ValidateSet('Install', 'Doctor', 'Uninstall', 'Purge')]
    [string]$Action = 'Install',
    [string]$Source = '.\infrascout.exe',
    [string]$Checksums = '',
    [string]$Prefix = "$env:LOCALAPPDATA\InfraScout",
    [string]$ConfirmPurge = ''
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath($Prefix)
$binDir = Join-Path $root 'bin'
$stateDir = Join-Path $root 'state'
$binary = Join-Path $binDir 'infrascout.exe'

switch ($Action) {
    'Install' {
        $sourcePath = [System.IO.Path]::GetFullPath($Source)
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw "Binary not found: $sourcePath" }
        if ($Checksums) {
            $name = Split-Path -Leaf $sourcePath
            $entry = Get-Content -LiteralPath $Checksums | Where-Object { $_ -match ('^[0-9a-fA-F]{64}\s+\*?' + [regex]::Escape($name) + '$') } | Select-Object -First 1
            if (-not $entry) { throw "Checksum entry not found for $name" }
            $expected = ($entry -split '\s+')[0].ToLowerInvariant()
            $actual = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) { throw "SHA-256 verification failed for $sourcePath" }
        }
        New-Item -ItemType Directory -Force -Path $binDir, $stateDir | Out-Null
        Copy-Item -LiteralPath $sourcePath -Destination $binary -Force
        & $binary version
        Write-Host "Installed $binary"
        Write-Host "State directory: $stateDir"
        Write-Warning 'Native host discovery is verified on Linux; Windows provides deterministic file review and demo viewing.'
    }
    'Doctor' {
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "InfraScout is not installed at $binary" }
        if (-not (Test-Path -LiteralPath $stateDir -PathType Container)) { throw "State directory is missing: $stateDir" }
        & $binary version
        Write-Host 'Doctor: binary and state directory are ready.'
    }
    'Uninstall' {
        Remove-Item -LiteralPath $binary -Force -ErrorAction SilentlyContinue
        if ((Test-Path -LiteralPath $binDir -PathType Container) -and -not (Get-ChildItem -LiteralPath $binDir -Force | Select-Object -First 1)) { Remove-Item -LiteralPath $binDir -Force }
        Write-Host "Removed InfraScout binaries; preserved $stateDir"
    }
    'Purge' {
        if ($ConfirmPurge -ne $root) { throw "Pass -ConfirmPurge with the exact path: $root" }
        if ((Split-Path -Leaf $root) -ne 'InfraScout') { throw "Refusing to purge unexpected path: $root" }
        Remove-Item -LiteralPath $root -Recurse -Force
        Write-Host "Purged $root"
    }
}
