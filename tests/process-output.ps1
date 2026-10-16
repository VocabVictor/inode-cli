$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/inode-process-output.ps1')
$psi = [Diagnostics.ProcessStartInfo]::new('python')
$psi.ArgumentList.Add('-u')
$psi.ArgumentList.Add('-c')
$psi.ArgumentList.Add("import sys,time; print('tunnel ready',flush=True); print('reconnect event',file=sys.stderr,flush=True); time.sleep(1); print('x'*70000,flush=True); sys.exit(7)")
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$process = [Diagnostics.Process]::Start($psi)
$events = [Collections.Generic.List[object]]::new()
$result = Receive-InodeProcessOutput -Process $process -OnLine {
    param($line)
    $events.Add([pscustomobject]@{ Text = $line; BeforeExit = -not $process.HasExited })
}
if ($result.ExitCode -ne 7) { throw 'Child exit code was lost' }
if (-not ($events | Where-Object { $_.Text -eq 'tunnel ready' -and $_.BeforeExit })) {
    throw 'Connection status was buffered until exit'
}
if (-not ($events | Where-Object { $_.Text -eq 'reconnect event' -and $_.BeforeExit })) {
    throw 'Stderr status was buffered until exit'
}
if ($result.Text.Length -gt 65536) { throw 'Diagnostic tail was not bounded' }
$process.Dispose()
'PASS: both pipes stream before exit, exit code retained, diagnostic tail bounded'
