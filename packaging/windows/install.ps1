# Install the fluxpeer daemon as a Windows service + fetch the wintun driver.
# Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Binary .\fluxpeer.exe
param(
  [string]$Binary = ".\fluxpeer.exe",
  [string]$InstallDir = "$Env:ProgramFiles\fluxpeer",
  [string]$WintunVersion = "0.14.1"
)
$ErrorActionPreference = "Stop"

# --- admin check ---
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  throw "Run this from an elevated (Administrator) PowerShell."
}
if (-not (Test-Path $Binary)) { throw "binary not found: $Binary (build with: cargo build --release -p fluxpeer)" }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $Binary (Join-Path $InstallDir "fluxpeer.exe") -Force
$ConfigDir = Join-Path $Env:ProgramData "fluxpeer"
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

# --- wintun.dll (TUN driver the data plane loads at runtime) ---
$arch = if ([Environment]::Is64BitOperatingSystem) {
  if ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else { "x86" }
$wintunDll = Join-Path $InstallDir "wintun.dll"
if (-not (Test-Path $wintunDll)) {
  $zip = Join-Path $Env:TEMP "wintun.zip"
  $url = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
  Write-Host "==> downloading wintun $WintunVersion ($arch) from $url"
  Invoke-WebRequest -Uri $url -OutFile $zip
  $tmp = Join-Path $Env:TEMP "wintun-extract"
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  Copy-Item (Join-Path $tmp "wintun\bin\$arch\wintun.dll") $wintunDll -Force
  Write-Host "==> installed $wintunDll"
}

# --- register the service ---
$svc = "fluxpeer"
$exe = Join-Path $InstallDir "fluxpeer.exe"
$nssm = (Get-Command nssm.exe -ErrorAction SilentlyContinue)?.Source
if ($nssm) {
  Write-Host "==> registering service via NSSM"
  & $nssm install $svc $exe "up"
  & $nssm set $svc AppDirectory $InstallDir
  & $nssm set $svc Start SERVICE_AUTO_START
  & $nssm start $svc
} else {
  Write-Host "==> NSSM not found; registering with sc.exe (basic)."
  Write-Host "    For clean start/stop + restart-on-crash, install NSSM (https://nssm.cc) and re-run."
  sc.exe create $svc binPath= "`"$exe`" up" start= auto | Out-Null
  sc.exe start $svc | Out-Null
}

Write-Host "done. Join a network:  fluxpeer.exe join `"fp://join/...`""
Write-Host "GUI reads the token at $ConfigDir\daemon.token"
