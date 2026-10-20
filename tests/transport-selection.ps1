$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../scripts/inode-transport.ps1')

function Check($condition, $message) { if (-not $condition) { throw $message } }
$calls = [Collections.Generic.List[string]]::new()
$probe = { param($candidate) $calls.Add([string]$candidate); $true }
$selected = Select-InodeTransport -Proxy 'http://proxy' -Probe $probe
Check ($selected.Ready -and $selected.Mode -eq 'direct') 'Direct must be preferred'
Check ($calls.Count -eq 1) 'Healthy direct path should not probe proxy'

$calls.Clear()
$probe = { param($candidate) $calls.Add([string]$candidate); [bool]$candidate }
$selected = Select-InodeTransport -Proxy 'http://proxy' -Probe $probe
Check ($selected.Ready -and $selected.Mode -eq 'proxy') 'Proxy fallback missing'
Check ($calls.Count -eq 2) 'Both paths must be attempted'

$selected = Select-InodeTransport -Proxy 'http://proxy' -Probe { $false }
Check (-not $selected.Ready) 'Unreachable paths must not authenticate'

$calls.Clear()
$selected = Select-InodeTransport -Proxy 'http://proxy' -ForceProxy -Probe {
    param($candidate) $calls.Add([string]$candidate); $true
}
Check ($selected.Mode -eq 'proxy' -and $calls.Count -eq 1) 'Explicit proxy must be preserved'
Write-Output 'PASS: direct preference, proxy fallback, outage gate, explicit proxy'
