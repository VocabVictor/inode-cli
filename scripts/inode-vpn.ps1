#Requires -Version 7
# iNode VPN 守护：读取 DPAPI 加密的密码，循环拉起 inode connect。
# inode 隧道断开先复用会话重连；短时恢复失败后由守护重新选择链路。
# 本脚本的循环退化为兜底：只有会话 Cookie 失效、需要重新登录时才会用到。
# 由计划任务 "inode-vpn"（最高权限）在登录时启动，也可手动运行。
# proxy.txt 提供备用代理；显式 -Proxy 才固定走代理。
param(
    [string]$Gateway = 'https://222.223.112.208:64441',
    [string]$ServerCert = '62A24E11C865EEDBD176363AB74C6473B8A24C75C1FB961EC002FBC74929854B',
    [string]$User = 'aicp-140',
    [string[]]$Routes = @('10.0.0.0/8','172.16.0.0/16','222.223.106.147/32','100.125.2.0/23'),
    [int]$RetryDelay = 3,
    # 显式指定时固定使用该 HTTP 代理。
    [string]$Proxy = ''
)
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'inode-process-output.ps1')
. (Join-Path $PSScriptRoot 'inode-transport.ps1')
$dir = Join-Path $env:LOCALAPPDATA 'inode'
$credFile = Join-Path $dir 'cred.dpapi'
$log = Join-Path $dir 'vpn.log'
$inode = Join-Path $env:USERPROFILE '.local\bin\inode.exe'
$forceProxy = $PSBoundParameters.ContainsKey('Proxy') -and [bool]$Proxy
Remove-Item Env:INODE_PROXY -ErrorAction SilentlyContinue

# 文件中的代理只在直连探测失败后使用。
$proxyFile = Join-Path $dir 'proxy.txt'
if (-not $Proxy -and (Test-Path -LiteralPath $proxyFile)) {
    $t = (Get-Content -LiteralPath $proxyFile -Raw).Trim()
    if ($t) { $Proxy = $t }
}

function Log($m) { "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m" | Tee-Object -FilePath $log -Append }

if (-not (Test-Path -LiteralPath $credFile)) { Log "缺少 $credFile，先运行 inode-vpn-setup.ps1"; exit 1 }
$sec = Get-Content -LiteralPath $credFile | ConvertTo-SecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($sec))

while ($true) {
    $transport = Select-InodeTransport -Proxy $Proxy -ForceProxy:$forceProxy -Probe {
        param($candidate)
        $probeArgs = @('probe', $Gateway, '--servercert', $ServerCert, '--timeout', '8')
        if ($candidate) { $probeArgs += @('--proxy', $candidate) }
        & $inode @probeArgs *> $null
        $LASTEXITCODE -eq 0
    }
    if (-not $transport.Ready) {
        Log "Gateway transport unavailable; no authentication attempted; retry in ${RetryDelay}s"
        Start-Sleep -Seconds $RetryDelay
        continue
    }
    Log "connect -> $Gateway (user $User, transport=$($transport.Mode))"
    $psi = [Diagnostics.ProcessStartInfo]::new($inode)
    foreach ($a in @('connect', $Gateway, '--servercert', $ServerCert, '--user', $User, '--password-stdin')) { $psi.ArgumentList.Add($a) }
    foreach ($r in $Routes) { $psi.ArgumentList.Add('--route'); $psi.ArgumentList.Add($r) }
    foreach ($a in @('--timeout', '8', '--reconnect-attempts', '2', '--keepalive', '15')) { $psi.ArgumentList.Add($a) }
    if ($transport.Proxy) { $psi.ArgumentList.Add('--proxy'); $psi.ArgumentList.Add($transport.Proxy) }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [Diagnostics.Process]::Start($psi)
    $p.StandardInput.WriteLine($plain)
    $p.StandardInput.Close()
    $result = Receive-InodeProcessOutput -Process $p -OnLine {
        param($line)
        if ($line.Trim()) { Log "  $($line.TrimEnd())" }
    }
    Log "inode exited code=$($result.ExitCode)"
    $text = $result.Text
    $p.Dispose()
    if ($text -match 'CAPTCHA auto-recognition failed') {
        Log "CAPTCHA recognition exhausted its bounded attempts; stopped to avoid lockout. This does not establish an incorrect password."
        exit 3
    }
    # 只匹配真正的认证失败。"CAPTCHA XXXX rejected (submit 1/3); refetching" 是
    # 验证码重抓的正常过程，之前裸匹配 'rejected' 会把成功的会话误判成认证失败，
    # 导致守护 exit 3 停摆（2026-09-14 至 09-16 就这样停了两天）。
    if ($text -match 'authentication failed|may lock the account|Password is required') {
        Log "认证类失败，停止自动重试以免锁号。请检查密码后重新运行 inode-vpn-setup.ps1"
        exit 3
    }
    Log "retry in ${RetryDelay}s"
    Start-Sleep -Seconds $RetryDelay
}
