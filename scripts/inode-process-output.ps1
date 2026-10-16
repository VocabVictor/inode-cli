function Receive-InodeProcessOutput {
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][scriptblock]$OnLine
    )
    # Drain both pipes while the tunnel is alive. Waiting for exit first hides
    # connection/reconnect events and gives all old events the same timestamp.
    $streams = @(
        @{ Reader = $Process.StandardOutput; Pending = $Process.StandardOutput.ReadLineAsync(); Done = $false },
        @{ Reader = $Process.StandardError; Pending = $Process.StandardError.ReadLineAsync(); Done = $false }
    )
    $tail = [Text.StringBuilder]::new()
    while (-not ($streams[0].Done -and $streams[1].Done)) {
        foreach ($stream in $streams) {
            while (-not $stream.Done -and $stream.Pending.IsCompleted) {
                $line = $stream.Pending.GetAwaiter().GetResult()
                if ($null -eq $line) { $stream.Done = $true; break }
                $null = & $OnLine $line
                $null = $tail.AppendLine($line)
                if ($tail.Length -gt 65536) {
                    $null = $tail.Remove(0, $tail.Length - 65536)
                }
                $stream.Pending = $stream.Reader.ReadLineAsync()
            }
        }
        if (-not ($streams[0].Done -and $streams[1].Done)) {
            Start-Sleep -Milliseconds 100
        }
    }
    $Process.WaitForExit()
    [pscustomobject]@{ Text = $tail.ToString(); ExitCode = $Process.ExitCode }
}
