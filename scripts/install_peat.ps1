<# 
Install-PEAT.ps1
Downloads PEAT for Windows and installs it for the current user.

Installs to:  $env:LOCALAPPDATA\Programs\peat.exe
Adds to PATH: HKCU:\Environment (user PATH)

Run in a regular (non-admin) PowerShell session.
#>

$ErrorActionPreference = "Stop"

$Repo = "sandialabs/PEAT"
$Url  = "https://github.com/$Repo/releases/latest/download/peat.exe"
$DestDir  = Join-Path $env:LOCALAPPDATA "Programs"
$DestExe  = Join-Path $DestDir "peat.exe"

function Add-ToUserPath([string]$Dir) {
    $regPath = "HKCU:\Environment"
    $name = "Path"

    $current = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).Path
    if (-not $current) { $current = "" }

    # Split PATH entries, normalize trailing slashes, compare case-insensitively
    $parts = $current -split ";" | Where-Object { $_ -and $_.Trim() -ne "" }
    $normalized = $parts | ForEach-Object { $_.Trim().TrimEnd("\") }

    $dirNorm = $Dir.Trim().TrimEnd("\")
    $already = $normalized | Where-Object { $_.Equals($dirNorm, [System.StringComparison]::OrdinalIgnoreCase) }

    if ($already) { return $false }

    $newPath = if ($current.Trim() -eq "") { $dirNorm } else { "$current;$dirNorm" }
    Set-ItemProperty -Path $regPath -Name $name -Value $newPath
    return $true
}

# Ensure destination directory exists
New-Item -ItemType Directory -Path $DestDir -Force | Out-Null

Write-Host "Downloading PEAT from:"
Write-Host "  $Url"
Write-Host "To:"
Write-Host "  $DestExe"

# Download
Invoke-WebRequest -Uri $Url -OutFile $DestExe -UseBasicParsing

# Add install directory to user PATH (so "peat.exe" is runnable as "peat")
$pathUpdated = Add-ToUserPath -Dir $DestDir

if ($pathUpdated) {
    Write-Host "Updated user PATH in registry (HKCU:\Environment)."
    Write-Host "You may need to open a new terminal (or sign out/in) for PATH changes to take effect."
} else {
    Write-Host "User PATH already contains: $DestDir"
}

Write-Host "Installed. Try running: peat --help"

