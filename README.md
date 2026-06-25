# Honeypot-Security-System

![Repo Visibility](https://img.shields.io/badge/visibility-Public-blue)
[![CI](https://github.com/kiurakku/Honeypot-Security-System/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/kiurakku/Honeypot-Security-System/actions/workflows/build-and-test.yml)
![License](https://img.shields.io/github/license/kiurakku/Honeypot-Security-System)

**Connect:** [![Author](https://img.shields.io/badge/GitHub-kiurakku-181717?style=flat-square&logo=github)](https://github.com/kiurakku) [![Telegram](https://img.shields.io/badge/Telegram-@SyntacticSugar-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/SyntacticSugar) [![Email](https://img.shields.io/badge/Email-yanginero%40outlook.com-0078D4?style=flat-square&logo=microsoftoutlook&logoColor=white)](mailto:yanginero@outlook.com)

Polyglot honeypot lab: **Flask** (attack logging), **Go** (HTTP request logging → Postgres), **C++** (demo traffic sampler), **nginx**, **Prometheus/Grafana**, **Terraform** (optional infra).

## Architecture

```
Client → nginx:80 → app:5000 (Flask /attack)
                 → go-service:8080 (/log → Postgres.logs)
Prometheus ← app:8000 (metrics)
C++ analyzer → logs/attacks.log (sidecar demo)
Postgres ← attacks + logs tables
```

## Quick Start

```bash
git clone https://github.com/kiurakku/Honeypot-Security-System.git
cd Honeypot-Security-System
cp .env.example .env   # optional — compose defaults work for dev
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| Flask app | http://localhost:5000 |
| Health | http://localhost:5000/health |
| Go logger | http://localhost:8080/log |
| nginx | http://localhost:80 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 |

### Log a test attack

```bash
curl -X POST http://localhost:5000/attack \
  -H 'Content-Type: application/json' \
  -d '{"attack_type":"ssh-bruteforce","source_ip":"203.0.113.10"}'

curl http://localhost:8080/log
```

Smoke script (Linux/macOS/WSL): `bash scripts/smoke-test.sh`

## Configuration

Усі сервіси використовують однакові змінні (див. `.env.example`):

| Variable | Default |
|----------|---------|
| `POSTGRES_DB` | `honeypot` |
| `POSTGRES_USER` | `honeypot` |
| `POSTGRES_PASSWORD` | `honeypot_secret` |

## Testing & CI

- **CI:** `build-and-test.yml` — збірка Go/C++, `docker compose` smoke test.
- Локально: `docker compose up -d db app go-service` → POST `/attack` → GET `/log`.

## Security Notes

- Лише для **лабораторного** використання; не виставляй у прод без ізоляції мережі.
- Не коміть реальні credentials; зміни пароль перед публічним деплоєм.

## License

GNU General Public License v3.0
