function Select-InodeTransport {
    param(
        [Parameter(Mandatory)][scriptblock]$Probe,
        [string]$Proxy = '',
        [switch]$ForceProxy
    )
    $candidates = if ($ForceProxy) { @($Proxy) } else { @(''); if ($Proxy) { $Proxy } }
    foreach ($candidate in $candidates) {
        if (& $Probe $candidate) {
            return [pscustomobject]@{
                Ready = $true
                Proxy = [string]$candidate
                Mode = $(if ($candidate) { 'proxy' } else { 'direct' })
            }
        }
    }
    [pscustomobject]@{ Ready = $false; Proxy = ''; Mode = 'unavailable' }
}
