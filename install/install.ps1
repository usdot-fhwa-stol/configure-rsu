#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 11 installer for Configure-RSU.
.DESCRIPTION
    Installs Python with winget (if needed), creates a virtual environment with the
    Python dependencies, writes a template src\.env file, and adds a Configure-RSU
    shortcut to the Desktop.

    Run from PowerShell:
        powershell -ExecutionPolicy Bypass -File .\install.ps1
#>

$ErrorActionPreference = 'Stop'

# Python version installed with winget when no suitable Python is found
$PythonVersion = '3.12'

# Run a native command and stop on a non-zero exit code (like `set -e`)
function Invoke-Checked {
    $exe, $rest = $args
    & $exe @rest
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $($args -join ' ')"
    }
}

# Return the full path of a working Python 3.9+ interpreter, or $null
function Test-Python {
    param([string]$Command, [string[]]$PrefixArgs = @())
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) { return $null }
    try {
        # Also rejects the Microsoft Store "python.exe" alias, which doesn't run Python
        $exe = & $Command @PrefixArgs -c 'import sys; print(sys.executable if sys.version_info >= (3, 9) else str())' 2>$null
    } catch {
        return $null
    }
    if ($LASTEXITCODE -eq 0 -and $exe -and (Test-Path $exe)) { return "$exe".Trim() }
    return $null
}

function Find-Python {
    if ($env:PYTHON) { return Test-Python $env:PYTHON }
    foreach ($candidate in @(@('py', '-3'), @('python'), @('python3'))) {
        $exe = Test-Python $candidate[0] @($candidate | Select-Object -Skip 1)
        if ($exe) { return $exe }
    }
    # Default per-user install location used by winget, in case PATH isn't updated yet
    $userInstall = Join-Path $env:LOCALAPPDATA "Programs\Python\Python$($PythonVersion -replace '\.', '')\python.exe"
    if (Test-Path $userInstall) { return Test-Python $userInstall }
    return $null
}

# Windows shortcuts can't use a PNG icon directly, but an .ico may embed PNG data as-is
function ConvertTo-Ico {
    param([string]$PngPath, [string]$IcoPath)
    $png = [IO.File]::ReadAllBytes($PngPath)
    # IHDR stores width/height as big-endian uint32 at offsets 16 and 20; ICO stores 256+ as 0
    $width, $height = 16, 20 | ForEach-Object {
        $value = [int]$png[$_ + 2] * 256 + $png[$_ + 3]
        if ($png[$_] -or $png[$_ + 1] -or $value -ge 256) { 0 } else { $value }
    }
    $header = [byte[]](0, 0, 1, 0, 1, 0, $width, $height, 0, 0, 1, 0, 32, 0) +
        [BitConverter]::GetBytes([uint32]$png.Length) +
        [BitConverter]::GetBytes([uint32]22)
    [IO.File]::WriteAllBytes($IcoPath, [byte[]]($header + $png))
}

# Declare local variables for paths and commands
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$VenvDir = if ($env:VENV_DIR) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:VENV_DIR)
} else {
    Join-Path $RepoRoot '.venv'
}

# Install Python if no suitable interpreter is available
$SystemPython = Find-Python
if (-not $SystemPython) {
    if ($env:PYTHON) {
        throw "PYTHON is set to '$env:PYTHON', but it is not a working Python 3.9+ interpreter."
    }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'Python 3 was not found and winget is unavailable. Install Python from https://www.python.org/downloads/windows/ and re-run this script.'
    }
    Write-Host "Python 3 not found. Installing Python $PythonVersion with winget..."
    & winget install --id "Python.Python.$PythonVersion" --exact --scope user --silent `
        --accept-package-agreements --accept-source-agreements

    # Pick up PATH changes made by the Python installer
    $env:Path = @(
        [Environment]::GetEnvironmentVariable('Path', 'Machine'),
        [Environment]::GetEnvironmentVariable('Path', 'User')
    ) -join ';'

    $SystemPython = Find-Python
    if (-not $SystemPython) {
        throw 'Python installation did not produce a usable interpreter. Install Python from https://www.python.org/downloads/windows/ and re-run this script.'
    }
}
Write-Host "Using Python at $SystemPython"

# Create venv if missing
$PythonBin = Join-Path $VenvDir 'Scripts\python.exe'
if (-not (Test-Path $PythonBin)) {
    Write-Host "Creating virtual environment at $VenvDir..."
    Invoke-Checked $SystemPython -m venv $VenvDir
}

# Upgrade pip in the venv (non-fatal)
& $PythonBin -m pip install --upgrade pip --quiet --disable-pip-version-check
if ($LASTEXITCODE -ne 0) { Write-Warning 'pip upgrade failed; continuing with the existing pip.' }

# Install Python dependencies from requirements.txt
$ReqFile = Join-Path $RepoRoot 'install\requirements.txt'
if (Test-Path $ReqFile) {
    Invoke-Checked $PythonBin -m pip install -r $ReqFile
} else {
    Write-Warning "requirements.txt not found at $ReqFile; skipping Python dependency install."
}

# Create .env file with SNMP credentials if it doesn't exist
$SrcEnvFile = Join-Path $RepoRoot 'src\.env'
if (-not (Test-Path $SrcEnvFile)) {
    # ASCII avoids the BOM that Windows PowerShell adds to UTF-8, which python-dotenv can't parse
    @(
        '# SNMP credentials'
        'IP_ADDRESS=your_rsu_ip_address'
        'SNMP_PORT=161'
        'SNMP_USER=your_snmp_username'
        'AUTH_PASSWORD=your_authentication_password'
        'PRIV_PASSWORD=your_privacy_password'
    ) | Set-Content -Path $SrcEnvFile -Encoding ascii
    Write-Host "`n.env file created at $SrcEnvFile"
} else {
    Write-Host "`n.env file already exists at $SrcEnvFile"
}

# Declare shortcut and icon paths
$IconSrc = Join-Path $RepoRoot 'src\desktop_app\rsu.png'
$UserDesktop = [Environment]::GetFolderPath('Desktop')  # follows OneDrive Desktop redirection
$LocalIconDir = Join-Path $env:LOCALAPPDATA 'ConfigureRSU'
$LocalIcon = Join-Path $LocalIconDir 'configure_rsu.ico'

# Create necessary directories
New-Item -ItemType Directory -Force -Path $LocalIconDir | Out-Null

# If icon does not exist, create a placeholder minimal PNG (white rectangle)
if (-not (Test-Path $IconSrc)) {
    Write-Warning 'Icon rsu.png not found. Creating placeholder icon.'
    New-Item -ItemType Directory -Force -Path (Split-Path $IconSrc) | Out-Null
    # 1x1 white PNG base64
    [IO.File]::WriteAllBytes($IconSrc, [Convert]::FromBase64String(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=='))
}

# Convert icon to .ico in the local app data directory
ConvertTo-Ico -PngPath $IconSrc -IcoPath $LocalIcon

# Create Desktop shortcut; pythonw.exe runs the GUI without a console window
$TargetShortcut = Join-Path $UserDesktop 'Configure-RSU.lnk'
$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($TargetShortcut)
$Shortcut.TargetPath = Join-Path $VenvDir 'Scripts\pythonw.exe'
$Shortcut.Arguments = '"{0}"' -f (Join-Path $RepoRoot 'src\configure_rsu.py')
$Shortcut.WorkingDirectory = Join-Path $RepoRoot 'src'
$Shortcut.IconLocation = "$LocalIcon,0"
$Shortcut.Description = 'UI for RSU Configuration'
$Shortcut.Save()

Write-Host "Installed desktop shortcut at $TargetShortcut"
Write-Host "Icon installed at $LocalIcon"
