<div align="center">

<img src="docs/assets/banner.svg" alt="DracoLure" width="100%">

# 🐉 DracoLure

**Dragon Vector Honeypot** — a polyglot deception honeypot that lures attackers, classifies every probe the instant it lands, scores the threat, and quarantines hostile sources — all in real time.

<!-- Status -->
[![Version](https://img.shields.io/badge/version-1.0.0-gold?style=flat-square)](VERSION)
[![Release](https://img.shields.io/github/v/tag/kiurakku/DracoLure?label=release&color=gold)](https://github.com/kiurakku/DracoLure/releases)
[![CI](https://github.com/kiurakku/DracoLure/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/kiurakku/DracoLure/actions/workflows/build-and-test.yml)
![License](https://img.shields.io/github/license/kiurakku/DracoLure?color=blue)
![Repo Visibility](https://img.shields.io/badge/visibility-Public-blue)
![Lab Use Only](https://img.shields.io/badge/scope-lab%20%2F%20research-important)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

<!-- Stack -->
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8?logo=go&logoColor=white)
![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-15-4169E1?logo=postgresql&logoColor=white)
![nginx](https://img.shields.io/badge/nginx-proxy-009639?logo=nginx&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-metrics-E6522C?logo=prometheus&logoColor=white)
![Grafana](https://img.shields.io/badge/Grafana-dashboards-F46800?logo=grafana&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-optional-7B42BC?logo=terraform&logoColor=white)

<!-- Embed -->
![REST API](https://img.shields.io/badge/REST-%2Fapi%2Fv1-6E56CF)
![Python SDK](https://img.shields.io/badge/SDK-Python-3776AB?logo=python&logoColor=white)
![Inject](https://img.shields.io/badge/inject-WSGI%20%2F%20ASGI-8B5CF6)
![Desktop](https://img.shields.io/badge/Desktop-Tkinter%20console-2EA44F)

**Connect:** [![Author](https://img.shields.io/badge/GitHub-kiurakku-181717?style=flat-square&logo=github)](https://github.com/kiurakku) [![Telegram](https://img.shields.io/badge/Telegram-@SyntacticSugar-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/SyntacticSugar) [![Email](https://img.shields.io/badge/Email-yanginero%40outlook.com-0078D4?style=flat-square&logo=microsoftoutlook&logoColor=white)](mailto:yanginero@outlook.com)

</div>

---

## 📸 Preview

<table>
<tr>
<td width="50%"><img src="docs/assets/dashboard-preview.svg" alt="Grafana threat dashboard" width="100%"><br><sub>📊 Live Grafana board — categories, severity, quarantines</sub></td>
<td width="50%"><img src="desktop/assets/console.svg" alt="Desktop console" width="100%"><br><sub>🖥️ Tkinter console — sources, events, block/unblock</sub></td>
</tr>
</table>

---

## 🎯 What it does

This is **not** a passive log sink. The moment a request touches the honeypot, a purpose-built sentinel runs on it — before any route executes:

1. 🪤 **Deceives** — serves believable bait (a fake corporate portal, a fake `/.env`, fake `wp-login`, `phpMyAdmin`, `/.git/config`) so an attacker keeps interacting instead of leaving.
2. 🔬 **Detects** — matches the request against a signature library (SQLi, XSS, path traversal, RCE, Log4Shell, webshells, template injection, scanners) with **URL-decode normalization** so encoded payloads can't slip past.
3. 📈 **Scores** — assigns a 0–100 threat score and a severity band (`low → critical`) to every interaction.
4. ⛓️ **Quarantines** — when a source crosses the threat threshold it is **auto-blocked** and tarpitted: it stops receiving bait and gets slowed 403s. *Self-contained and defensive — the honeypot only changes how it answers its own traffic; it never touches the attacker's host.*
5. 📊 **Observes** — every event flows to Postgres and to Prometheus, and a live Grafana dashboard shows the picture as it happens.

> ⚠️ **Ethics & scope.** This is a **defensive** research/lab tool. It observes, records, and slows hostile traffic against *its own* surface. It performs no scanning, no exploitation, and no "hack-back." Run it only on infrastructure you own or are authorized to test.

---

## ✨ Highlights

| | Capability | Detail |
|---|------------|--------|
| 🪤 | **Deception surface** | Fake landing page + bait endpoints that never reveal they're a honeypot |
| ⚡ | **Instant classification** | Every request analysed in `before_request` — zero-delay detection |
| 🧬 | **Encoding-aware engine** | Scans raw **and** percent-decoded (incl. double-encoded) payloads |
| 🎚️ | **Threat scoring** | Weighted per-category scoring, capped 0–100, 4 severity bands |
| ⛓️ | **Auto-quarantine + tarpit** | Rolling per-IP scoring, TTL blocklist, slowed 403 responses |
| 🛡️ | **Fail-open resilience** | If Postgres blinks, events still hit stdout — the sensor never crashes |
| 📊 | **Live dashboards** | Prometheus metrics + provisioned Grafana board, out of the box |
| 🧪 | **Tested** | Go + C++ builds, Python detection/API/SDK tests, compose smoke test in CI |
| 🧩 | **Embeddable** | REST `/api/v1`, stdlib Python SDK, one-line WSGI/ASGI middleware, Docker |
| 🖥️ | **Desktop console** | Tkinter GUI (stdlib) — live sources, events feed, block/unblock |
| 🌐 | **Polyglot** | Flask · Go · C++ · nginx · Postgres · Prometheus · Grafana |

---

## 🏗️ Architecture

```mermaid
flowchart LR
    A([🌐 Attacker / Scanner]) -->|HTTP| N[nginx :80]
    Apps["🧩 Your apps<br/>SDK · middleware"] -->|/api/v1/ingest| F
    N -->|/ and traps| F["🐍 DracoLure :5000<br/>sentinel · detection · quarantine · /api/v1"]
    N -->|/log| G["🐹 Go logger :8080"]
    F -->|classified events| DB[("🐘 Postgres<br/>attacks · logs · honeypot_events")]
    G -->|request logs| DB
    F -->|/metrics :8000| P["📡 Prometheus :9090"]
    P --> Gr["📊 Grafana :3000<br/>Live Threat Activity"]
    Console["🖥️ Desktop console"] -->|/api/v1 stats · events · block| F
    C["⚙️ C++ analyzer<br/>(sidecar demo)"] -.-> L[["logs/attacks.log"]]
```

### 🔎 Detection pipeline

```mermaid
flowchart LR
    R[Incoming request] --> Q{Source<br/>quarantined?}
    Q -->|yes| T[⏳ Tarpit 403]
    Q -->|no| D[🔬 Analyze<br/>path · query · body · UA]
    D --> S{Malicious?}
    S -->|score = 0| B[Serve bait / 404<br/>no noise logged]
    S -->|score > 0| Sc[📈 Score + classify]
    Sc --> Rec[💾 Persist + 📡 metrics]
    Rec --> Th{Over<br/>threshold?}
    Th -->|yes| BL[⛓️ Quarantine source]
    Th -->|no| Bait[Serve bait / 404]
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/kiurakku/DracoLure.git
cd DracoLure
cp .env.example .env   # optional — compose defaults work for dev
docker compose up -d --build
```

| Service | URL | Purpose |
|---------|-----|---------|
| 🐍 Flask honeypot | http://localhost:5000 | Deception surface + detection engine |
| ❤️ Health | http://localhost:5000/health | Liveness / DB status |
| 📊 Honeypot stats | http://localhost:5000/honeypot/stats | Live threat snapshot (JSON) |
| 🧩 Integration API | http://localhost:5000/api/v1 | Ingest · stats · events · block/unblock |
| 🐹 Go logger | http://localhost:8080/log | Raw request logging |
| 🔀 nginx | http://localhost:80 | Reverse proxy / edge |
| 📡 Prometheus | http://localhost:9090 | Metrics store |
| 📊 Grafana | http://localhost:3000 | **"DracoLure — Live Threat Activity"** dashboard |

> Grafana ships with anonymous **Viewer** access enabled and the dashboard auto-provisioned — open it and the panels are already wired to Prometheus.

---

## 🎬 See it in action

Fire a batch of representative probes and watch the engine light up:

```bash
# Linux / macOS / WSL
bash scripts/simulate-attacks.sh
```

```powershell
# Windows PowerShell
./scripts/simulate-attacks.ps1
```

Then read the live snapshot:

```bash
curl -s http://localhost:5000/honeypot/stats
```

```jsonc
{
  "tracked_sources": 5,
  "blocked_now": 1,
  "blocks_total": 1,
  "block_threshold": 100,
  "top_sources": [
    { "ip": "10.10.10.10", "score": 100, "hits": 5, "blocked": true },
    { "ip": "192.0.2.99",  "score": 100, "hits": 3, "blocked": false }
  ]
}
```

Open **Grafana → DracoLure — Live Threat Activity** to see intrusions-by-category, severity breakdown, quarantines, and average threat score update every few seconds.

### Log a single attack manually

```bash
curl -X POST http://localhost:5000/attack \
  -H 'Content-Type: application/json' \
  -d '{"attack_type":"ssh-bruteforce","source_ip":"203.0.113.10"}'
```

---

## 🧩 Embed DracoLure anywhere

DracoLure doubles as a central **detection service**. Your own apps report
requests to it over `/api/v1`; it classifies each one, tracks the source, and
returns a verdict you can act on. Four ways to plug in — full guide in
[`integrations/`](integrations/).

**One-line middleware injection** (any WSGI app — Flask/Django/…):

```python
from dracolure import DracoLureClient, DracoLureMiddleware
app.wsgi_app = DracoLureMiddleware(app.wsgi_app,
                                   DracoLureClient("http://dracolure:5000"),
                                   mode="block")   # or "monitor" (zero-latency)
```

**SDK / REST** (stdlib-only client, or plain HTTP from any language):

```python
from dracolure import DracoLureClient
c = DracoLureClient("http://localhost:5000")
v = c.ingest(method="GET", path="/x", query="id=1' OR 1=1--", source_ip="203.0.113.5")
print(v.recommendation, v.score, v.categories)   # -> monitor 40 ['sql-injection']
```

```bash
curl -s -X POST http://localhost:5000/api/v1/ingest -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/x","query":"id=1'\'' OR 1=1--","source_ip":"203.0.113.5"}'
```

| Integration | Best for | Reference |
|-------------|----------|-----------|
| 🧩 Middleware (WSGI/ASGI) | Existing web apps, no route changes | [examples/flask_app.py](integrations/examples/flask_app.py) · [fastapi_app.py](integrations/examples/fastapi_app.py) |
| 🐍 Python SDK | Scripts, pipelines, custom logic | [python-sdk/](integrations/python-sdk) |
| 🌐 REST `/api/v1` | Any language | [examples/curl.md](integrations/examples/curl.md) · [node_client.js](integrations/examples/node_client.js) |
| 🐳 Docker | Shared service on a compose network | [docker/](integrations/docker) |

> The middleware is **fail-open** (your app keeps serving if DracoLure is down)
> and never consumes the request body, so it can't break downstream handlers.

---

## 🖥️ Desktop console

A cross-platform GUI ([`desktop/`](desktop/)) — Python **Tkinter**, standard
library only — connects to a running server and shows the live threat picture
with one-click quarantine control.

```bash
python desktop/dracolure_console.py --url http://localhost:5000
```

---

## 🧬 Detection coverage

| Category | Example payload | Weight |
|----------|-----------------|:------:|
| 💉 `sql-injection` | `id=1' OR 1=1--`, `UNION SELECT`, `pg_sleep()` | 40 |
| 🧨 `command-injection` | `;cat /etc/passwd`, `` `whoami` ``, `$(id)` | 50 |
| 🕳️ `log4shell` | `${jndi:ldap://…}` | 50 |
| 🐚 `webshell` | `base64_decode(`, `system(`, `passthru(` | 45 |
| 📁 `path-traversal` | `../../../../etc/passwd`, `%2e%2e%2f` | 35 |
| 🔑 `credential-access` | `/.env`, `/.git/`, `/.aws/`, `id_rsa` | 30 |
| 🧩 `template-injection` | `{{7*7}}`, `${…}`, `<%= … %>` | 30 |
| 🩹 `xss` | `<script>`, `onerror=`, `javascript:` | 25 |
| 🛰️ `recon-scanner` | `sqlmap`, `nikto`, `/wp-login.php`, `/phpmyadmin` | 20 |

Scores are **summed and capped at 100**. Severity bands: `low` (1–24) · `medium` (25–49) · `high` (50–79) · `critical` (80–100).

---

## 📡 Metrics (Prometheus)

| Metric | Type | Labels |
|--------|------|--------|
| `honeypot_events_total` | counter | `category`, `severity` |
| `honeypot_blocks_total` | counter | — |
| `honeypot_tarpit_total` | counter | — |
| `honeypot_threat_score` | histogram | — |
| `request_processing_seconds` | summary | — |

---

## ⚙️ Configuration

All services share the same variables (see [`.env.example`](.env.example)):

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `honeypot` | Database name |
| `POSTGRES_USER` | `honeypot` | Database user |
| `POSTGRES_PASSWORD` | `honeypot_secret` | Database password *(change before any exposure)* |
| `HONEYPOT_BLOCK_THRESHOLD` | `100` | Cumulative score that triggers quarantine |
| `HONEYPOT_WINDOW_SECONDS` | `300` | Rolling scoring window |
| `HONEYPOT_BLOCK_TTL` | `600` | Quarantine duration (seconds) |
| `HONEYPOT_TARPIT_SECONDS` | `1.5` | Delay applied to quarantined sources |
| `DRACOLURE_API_KEY` | *(unset)* | If set, every `/api/v1` call must send `X-API-Key` |

---

## 🧪 Testing & CI

- **CI** ([`build-and-test.yml`](.github/workflows/build-and-test.yml)) — builds Go & C++, runs Go unit tests, runs the **Python detection + API tests** and the **SDK middleware tests**, then a `docker compose` integration smoke test.
- **Locally:**

```bash
# Detection engine + API tests (app/tests)
cd app && python -m pytest tests/ -q

# SDK / middleware tests
cd integrations/python-sdk && python -m pytest tests/ -q

# Go unit tests
cd backend/go-service && go test ./...

# Full-stack smoke test (Linux/macOS/WSL)
bash scripts/smoke-test.sh
```

---

## 🗂️ Project layout

```text
DracoLure/
├─ app/                     # 🐍 Flask honeypot + /api/v1
│  ├─ main.py               #   sentinel, routing, quarantine wiring
│  ├─ detection.py          #   signature engine (pure, unit-tested)
│  ├─ threat.py             #   per-IP scoring + quarantine store
│  ├─ decoys.py             #   deceptive bait responses (all fake)
│  ├─ api.py                #   /api/v1 integration surface
│  ├─ database.py           #   resilient persistence
│  └─ tests/                #   pytest detection / threat / API tests
├─ integrations/            # 🧩 embed DracoLure elsewhere
│  ├─ python-sdk/           #   stdlib client + injectable middleware (+ tests)
│  ├─ examples/             #   Flask, FastAPI, curl, Node
│  └─ docker/               #   shared-service compose
├─ desktop/                 # 🖥️ Tkinter threat console
├─ backend/
│  ├─ go-service/           # 🐹 Go request logger → Postgres
│  └─ cpp-analyzer/         # ⚙️ C++ sidecar (demo)
├─ db/                      # 🐘 schema, migrations, seeds
├─ monitoring/             # 📡 Prometheus + 📊 Grafana provisioning
├─ nginx/                   # 🔀 reverse proxy
├─ infrastructure/terraform # ☁️ optional infra
├─ scripts/                 # 🎬 smoke + attack-simulation scripts
└─ docker-compose.yml
```

---

## 🛡️ Security notes

- 🧪 **Lab / research use only.** Do not expose to the public internet without strong network isolation (dedicated VLAN, firewalling, no lateral access to real assets).
- 🔑 **Rotate credentials.** The default Postgres and Grafana passwords are placeholders — change them before any deployment.
- 🪤 **Bait is fabricated.** Every "secret" the honeypot serves is fake and exists only to keep attackers engaged and profiled.
- 📜 **Authorized use.** Only deploy against infrastructure you own or have explicit permission to test.

---

## 🗺️ Roadmap

- [ ] Webhook/Slack alerting on `critical` events
- [ ] GeoIP + ASN enrichment for source IPs
- [ ] Persisted blocklist (survive restarts) + shared store across replicas
- [ ] Additional protocol emulators (SSH / SMTP) beyond HTTP
- [ ] Grafana alert rules on quarantine spikes

---

## 📄 License

Distributed under the **GNU General Public License v3.0** — see [`LICENSE`](LICENSE).

<div align="center">

Built with 🐉 by [**kiurakku**](https://github.com/kiurakku) · *lure them into the dragon's vector.*

</div>
