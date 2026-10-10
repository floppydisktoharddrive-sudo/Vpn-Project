param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8080,
    [int]$EverySec = 8,
    [int]$HangSec = 180,
    [int]$GraceSec = 600,
    [string]$ServerExe = "",
    [string]$ModelPath = "",
    [int]$Ctx = 8192,
    [int]$Ngl = 99
)

$ErrorActionPreference = "SilentlyContinue"
$base = "http://${HostName}:${Port}"
$endpoints = @("$base/health", "$base/v1/models", "$base/props")
$started = Get-Date
$lastOk = $null
Write-Host "[watchdog] watching $base  every ${EverySec}s"
Write-Host "[watchdog] startup grace ${GraceSec}s before a restart is allowed"

function Test-Api {
    foreach ($uri in $endpoints) {
        try {
            $resp = Invoke-WebRequest -Uri $uri -TimeoutSec 4 -UseBasicParsing
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { return $true }
        } catch {}
    }
    return $false
}

function Restart-Server {
    Write-Host "[watchdog] rebinding: restart llama-server"
    Get-Process -Name "llama-server","server" -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    if (-not (Test-Path -LiteralPath $ServerExe)) {
        Write-Host "[watchdog] missing exe: $ServerExe"
        return
    }
    $args = @(
        "-m", $ModelPath,
        "--host", $HostName,
        "--port", "$Port",
        "-c", "$Ctx",
        "-ngl", "$Ngl"
    )
    Start-Process -FilePath $ServerExe -ArgumentList $args -WindowStyle Minimized
    $script:started = Get-Date
    $script:lastOk = $null
    Start-Sleep -Seconds 6
}

while ($true) {
    if (Test-Api) {
        if ($null -eq $lastOk) { Write-Host ("[watchdog] {0} API up" -f (Get-Date -Format T)) }
        $lastOk = Get-Date
    } else {
        $elapsed = ((Get-Date) - $started).TotalSeconds
        if ($elapsed -lt $GraceSec -and $null -eq $lastOk) {
            Write-Host ("[watchdog] {0} still loading ({1:N0}s / {2}s grace)" -f (Get-Date -Format T), $elapsed, $GraceSec)
        } else {
            $anchor = $lastOk
            if ($null -eq $anchor) { $anchor = $started }
            $gone = ((Get-Date) - $anchor).TotalSeconds
            Write-Host ("[watchdog] {0} API down for {1:N0}s" -f (Get-Date -Format T), $gone)
            if ($gone -ge $HangSec) { Restart-Server }
        }
    }
    Start-Sleep -Seconds $EverySec
}
