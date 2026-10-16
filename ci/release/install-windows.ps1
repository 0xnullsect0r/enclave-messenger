# Install a release's Windows installer silently, start the app until its
# vault shows its first state, and uninstall (release.yml `install-windows`).
#
#   ./ci/release/install-windows.ps1 -Kind msi|nsis|msix -Dist DIR
param(
    [Parameter(Mandatory)] [ValidateSet('msi', 'nsis', 'msix')] [string] $Kind,
    [Parameter(Mandatory)] [string] $Dist
)
$ErrorActionPreference = 'Stop'

function Run-App([string] $exe, [string[]] $arguments) {
    # A GUI program: wait for it, and read what it printed from files.
    $out = New-TemporaryFile
    $err = New-TemporaryFile
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError $err
    Get-Content $out, $err | Write-Host
    if ($p.ExitCode -ne 0) { throw "$exe $arguments exited with $($p.ExitCode)" }
    Get-Content $out
}

if ($Kind -eq 'msi') {
    $msi = Get-ChildItem $Dist -Filter 'Enclave-*-x86_64.msi' | Select-Object -First 1
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn /l*v msi-install.log" -Wait -PassThru
    if ($p.ExitCode -ne 0) { Get-Content msi-install.log -Tail 50; throw "msiexec /i: $($p.ExitCode)" }
    $dir = Join-Path $env:ProgramFiles 'Enclave'
} elseif ($Kind -eq 'msix') {
    # Unsigned until a certificate exists: its publisher carries the OID
    # that lets Windows install it with -AllowUnsigned.
    $msix = Get-ChildItem $Dist -Filter 'Enclave-*-x86_64.msix' | Select-Object -First 1
    Add-AppxPackage -Path $msix.FullName -AllowUnsigned
    $dir = (Get-AppxPackage -Name 'com.aricummings.Enclave').InstallLocation
    if (-not $dir) { throw 'the package is not installed' }
} else {
    $setup = Get-ChildItem $Dist -Filter 'Enclave-*-x86_64-setup.exe' | Select-Object -First 1
    $p = Start-Process $setup.FullName -ArgumentList '/S' -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "setup /S: $($p.ExitCode)" }
    $dir = Join-Path $env:LOCALAPPDATA 'Enclave'
}

$exe = Join-Path $dir 'enclave.exe'
foreach ($program in 'enclave', 'enclave-vault', 'enclave-netd', 'enclave-mediad', 'enclave-tord', 'enclave-nymd', 'lyrebird') {
    if (-not (Test-Path (Join-Path $dir "$program.exe"))) { throw "$program.exe isn't installed in $dir" }
}
# The Start menu shortcut carries the app id toasts are sent under (a
# package has its own Start menu entry).
if ($Kind -ne 'msix') {
$shortcut = Get-ChildItem -Recurse -Filter 'Enclave.lnk' `
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs" `
    -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $shortcut) { throw 'no Start menu shortcut' }
}

$version = Run-App $exe @('--version')
if (-not ($version -match '^enclave ')) { throw "--version printed '$version'" }
$env:SLINT_BACKEND = 'winit-software'
Run-App $exe @('--smoke-exit') | Out-Null
$profiles = @(Join-Path $env:LOCALAPPDATA 'aricummings\Enclave') +
    @(Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Packages') -Filter 'com.aricummings.Enclave_*' -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'LocalCache\Local\aricummings\Enclave' })
if (-not ($profiles | Where-Object { Test-Path $_ })) {
    Get-ChildItem $env:LOCALAPPDATA | Write-Host
    throw 'no profile in the app data folder'
}

if ($Kind -eq 'msix') {
    Get-AppxPackage -Name 'com.aricummings.Enclave' | Remove-AppxPackage
} elseif ($Kind -eq 'msi') {
    $p = Start-Process msiexec.exe -ArgumentList "/x `"$($msi.FullName)`" /qn" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec /x: $($p.ExitCode)" }
} else {
    $p = Start-Process (Join-Path $dir 'uninstall.exe') -ArgumentList '/S' -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "uninstall /S: $($p.ExitCode)" }
    # The uninstaller copies itself and returns before it is done.
    for ($i = 0; $i -lt 60 -and (Test-Path $exe); $i++) { Start-Sleep 1 }
}
if (Test-Path $exe) { throw 'enclave.exe is still there after uninstalling' }
Write-Host "install-windows: $Kind ok"
