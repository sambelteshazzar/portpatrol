# PortPatrol installer for Windows.
# Usage: powershell -ExecutionPolicy Bypass -File install.ps1
# Builds a private virtual environment, writes a user-scope PATH entry the
# registry-preserving way, and places a Start Menu shortcut.

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    Write-Host "portpatrol install: $Message"
    exit 2
}

function Find-Python {
    $script:PythonCommand = $null
    $script:PythonPrefix = @()
    $script:PythonVersion = $null
    try {
        $out = (& py -3 -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $out) {
            $script:PythonCommand = 'py'
            $script:PythonPrefix = @('-3')
            $script:PythonVersion = $out
            return
        }
    } catch { }
    try {
        $out = (& python -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $out) {
            $script:PythonCommand = 'python'
            $script:PythonVersion = $out
            return
        }
    } catch { }
}

function Add-UserPath([string]$Directory) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -eq $key) { return $false }
    try {
        $raw = ''
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($key.GetValueNames() -contains 'Path') {
            $raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind('Path')
        }
        $entries = @()
        foreach ($entry in $raw.Split(';')) {
            $trimmed = $entry.TrimEnd('\')
            if ($trimmed -and $trimmed -ne $Directory.TrimEnd('\')) { $entries += $entry }
        }
        $entries += $Directory
        $key.SetValue('Path', ($entries -join ';'), $kind)
        return $true
    } finally {
        $key.Close()
    }
}

function Broadcast-EnvironmentChange {
    if (-not ('PortPatrol.NativeMethods' -as [type])) {
        Add-Type -Namespace PortPatrol -Name NativeMethods -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    [void][PortPatrol.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

Find-Python
if (-not $PythonCommand) {
    Fail "no Python 3 found. Install Python 3.8 or newer from https://www.python.org/downloads/ and check 'Add python.exe to PATH'."
}

$versionParts = $PythonVersion.Split('.')
$major = [int]$versionParts[0]
$minor = [int]$versionParts[1]
$minVersion = (3, 8)
if ($major -lt $minVersion[0] -or ($major -eq $minVersion[0] -and $minor -lt $minVersion[1])) {
    Fail "Python $PythonVersion is too old; version 3.8 or newer is required."
}

$rootDir = Join-Path $env:USERPROFILE '.portpatrol'
$venvDir = Join-Path $rootDir 'venv'
$venvPython = Join-Path $venvDir 'Scripts\python.exe'
$venvExe = Join-Path $venvDir 'Scripts\portpatrol.exe'
$binDir = Join-Path $rootDir 'bin'
$srcDir = $PSScriptRoot

New-Item -ItemType Directory -Force -Path $rootDir | Out-Null
& $PythonCommand @PythonPrefix -m venv $venvDir
if ($LASTEXITCODE -ne 0) { Fail "could not create the virtual environment at $venvDir." }
if (-not (Test-Path $venvPython)) { Fail "the virtual environment is missing $venvPython." }

& $venvPython -m pip install --quiet --upgrade $srcDir
if ($LASTEXITCODE -ne 0) {
    Fail "the pip install failed. The first run downloads a small build package, so an internet connection is needed."
}

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$shim = Join-Path $binDir 'portpatrol.bat'
@"
@echo off
"$venvExe" %*
"@ | Set-Content -Path $shim -Encoding Ascii

$desktopLauncher = Join-Path $binDir 'portpatrol-desktop.bat'
@"
@echo off
"$venvExe" scan
echo.
echo Press Enter to close...
pause
"@ | Set-Content -Path $desktopLauncher -Encoding Ascii

if (-not (Add-UserPath $binDir)) {
    Fail "cannot update the user PATH in the registry."
}
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')
Broadcast-EnvironmentChange

try {
    $programs = [Environment]::GetFolderPath('Programs')
    $shortcutPath = Join-Path $programs 'PortPatrol.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $desktopLauncher
    $shortcut.WorkingDirectory = $binDir
    $shortcut.Description = 'Scan localhost for open ports'
    $shortcut.Save()
} catch {
    Write-Host "portpatrol install: the Start Menu shortcut could not be created; the launcher is at $desktopLauncher"
}

Write-Host "PortPatrol installed. Open a new terminal and run: portpatrol"
Write-Host "The PortPatrol shortcut is in your Start Menu; it opens a scan and waits for Enter."
exit 0
