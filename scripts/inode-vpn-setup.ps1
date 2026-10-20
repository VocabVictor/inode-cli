#Requires -Version 7
$ErrorActionPreference = 'Stop'
$taskName = 'inode-vpn'
$directory = Join-Path $env:LOCALAPPDATA 'inode'
$credentialPath = Join-Path $directory 'cred.dpapi'
$password = Read-Host 'Enter the current VPN password (hidden; not a password change)' -AsSecureString
if ($password.Length -eq 0) { throw 'Empty password; saved credentials unchanged.' }
$confirmation = Read-Host 'Enter it again' -AsSecureString
function Reveal([Security.SecureString]$value) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($value)
    try { [Runtime.InteropServices.Marshal]::PtrToStringUni($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($pointer) }
}
try {
    if ((Reveal $password) -cne (Reveal $confirmation)) {
        throw 'Passwords differ; saved credentials unchanged.'
    }
    if ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
        throw 'VPN task is running; saved credentials unchanged.'
    }
    $null = New-Item -ItemType Directory -Path $directory -Force
    $encrypted = ConvertFrom-SecureString $password
    [IO.File]::WriteAllText($credentialPath, $encrypted)
    Start-ScheduledTask -TaskName $taskName
    Write-Host 'Saved using Windows DPAPI. Automatic VPN login started.'
    Write-Host "Check: Get-Content '$directory\vpn.log' -Tail 8"
} finally {
    $password.Dispose()
    $confirmation.Dispose()
}
