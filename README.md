# ▓▓ KitSentinel

**Security Posture Management Platform** — CLI & TUI

KitSentinel adalah platform analisis risiko keamanan yang beroperasi sepenuhnya via terminal.
Menggabungkan Golang Core Engine dengan Python Intelligence Engine untuk memberikan:

- Asset Inventory & Discovery
- Security Posture Assessment (TLS, Headers, DNS, Cookies, CSP)
- Exposure Management (Admin panels, config leaks, debug pages)
- Risk Scoring Engine (multi-layer weighted scoring)
- Trend Analytics (7d, 30d, 90d, 1y historical trends)
- Recommendation Engine (prioritized remediation steps)
- Report Generation (text, JSON, HTML, CSV)
- Interactive TUI (Bubble Tea dark-mode terminal dashboard)

---

## Installation

### Prerequisites

```bash
# Go 1.22+
go version

# GCC (required for CGO/SQLite)
sudo apt install gcc   # Ubuntu/Debian
brew install gcc       # macOS

# Python 3.10+ (for Intelligence Engine)
python3 --version
```

### Build from source

```bash
git clone https://github.com/kitsentinel/cli
cd kitsentinel-cli

# Install dependencies and build
make deps
make build

# Install to /usr/local/bin
make install
```

### Manual build

```bash
CGO_ENABLED=1 go build -o kitsentinel ./cmd/kitsentinel/main.go
sudo mv kitsentinel /usr/local/bin/
```

---

## Quick Start

```bash
# 1. Initialize configuration
kitsentinel init

# 2. Scan your first target
kitsentinel inventory --target example.com

# 3. Launch interactive TUI
kitsentinel tui

# 4. View security status
kitsentinel status
```

---

## Commands

| Command | Description |
|---------|-------------|
| `kitsentinel init` | Initialize config and database |
| `kitsentinel inventory --target <domain>` | Discover and assess assets |
| `kitsentinel assess` | Re-assess all known assets |
| `kitsentinel risk` | Calculate & display risk scores |
| `kitsentinel analytics --period 30d` | View trend analytics |
| `kitsentinel reports --format html` | Generate security report |
| `kitsentinel certificates` | Show SSL certificate status |
| `kitsentinel assets` | List all assets |
| `kitsentinel status` | Quick security posture overview |
| `kitsentinel tui` | Launch interactive TUI |

### Flags

```bash
kitsentinel inventory --target "example.com,api.example.com"
kitsentinel analytics --period 7d        # 24h | 7d | 30d | 90d | 1y
kitsentinel reports --format html        # text | json | html | csv
kitsentinel reports --format json --period 30d
kitsentinel --db /path/to/custom.db tui  # custom database path
kitsentinel --quiet status               # suppress banner
```

---

## TUI Navigation

```
╔═══════════════════════════════════════════════════════════════════╗
║  ▓ KitSentinel                 ● ACTIVE    [r] Refresh  [q] Quit ║
╠═══════════════╦═══════════════════════════════════════════════════╣
║ OVERVIEW      ║  SECURITY DASHBOARD                               ║
║ ⬡ Dashboard   ║                                                   ║
║               ║  Security Score  Assets   Findings  Exposures     ║
║ ASSETS        ║  ██ 72/100 B    247       23 ⚠      7 ⚠          ║
║ ◈ Inventory   ║                                                   ║
║ ⊛ Security    ║  CRITICAL ██░░░░░░░░  6                           ║
║               ║  HIGH     ████░░░░░░  11                          ║
║ SECURITY      ║  MEDIUM   ██░░░░░░░░  6                           ║
║ ⚠ Exposures   ║  LOW      ░░░░░░░░░░  0                           ║
║ ◉ Certs       ║                                                   ║
║ ⬡ DNS         ╠═══════════════════════════════════════════════════╣
║               ║  RECENT FINDINGS                                  ║
║ INTELLIGENCE  ║  [CRITICAL]  Exposed Admin Panel                  ║
║ ◎ Risk        ║  [HIGH    ]  Missing HSTS Header                  ║
║ ∿ Analytics   ║  [HIGH    ]  Weak TLS 1.0 Active                  ║
║ ◑ Recs        ║  [MEDIUM  ]  DMARC Not Configured                 ║
╠═══════════════╬═══════════════════════════════════════════════════╣
║ ▓▓ KitSentinel v1.0.0  │  Assets:247  Critical:6  │  ↑↓ navigate ║
╚═══════════════╩═══════════════════════════════════════════════════╝
```

**Keys:**
- `↑` / `↓` or `j` / `k` — Navigate menu
- `1`–`9` — Quick jump to section
- `Enter` / `Space` — Select
- `r` — Refresh data
- `q` — Quit
- `?` — Help

---

## Python Intelligence Engine

```bash
# Risk scoring
python3 python/risk_engine/risk_engine.py ~/.kitsentinel/sentinel.db --format text

# Trend analytics
python3 python/analytics/trend_analytics.py ~/.kitsentinel/sentinel.db --days 30 --format text

# Recommendation engine
python3 python/recommendation/recommendation_engine.py ~/.kitsentinel/sentinel.db --format text
```

---

## Configuration

Config file: `~/.kitsentinel/config.yaml`

```yaml
targets:
  - example.com
  - api.example.com

database_path: ~/.kitsentinel/sentinel.db
output_dir: ~/.kitsentinel/reports

timeout_seconds: 30
worker_count: 20
user_agent: "KitSentinel/1.0 Security Scanner"

log_level: info
python_bin: python3
```

Environment variable overrides: `KITSENTINEL_<KEY>` (e.g. `KITSENTINEL_DATABASE_PATH`)

---

## Project Structure

```
kitsentinel-cli/
├── cmd/kitsentinel/
│   └── main.go                    # CLI entry point (all commands)
├── internal/
│   ├── engine/
│   │   ├── assessment/scanner.go  # TLS, headers, DNS, exposure scanner
│   │   ├── risk/engine.go         # Risk score calculation
│   │   ├── analytics/engine.go    # Trend analytics + sparklines
│   │   ├── recommendation/        # Remediation recommendation engine
│   │   └── report/engine.go       # text/JSON/HTML/CSV report generation
│   ├── tui/
│   │   ├── styles/theme.go        # Cybersecurity dark theme (lipgloss)
│   │   └── views/                 # All TUI views (dashboard, assets, findings...)
│   ├── storage/sqlite.go          # SQLite data layer (all CRUD)
│   └── models/models.go           # All domain models
├── python/
│   ├── risk_engine/               # ML-weighted risk correlation
│   ├── analytics/                 # Historical trend analytics
│   └── recommendation/            # Prioritized recommendation engine
├── configs/config.yaml            # Default configuration
├── Makefile
└── README.md
```

---

## What KitSentinel Detects

### Security Headers
- Missing HSTS
- Missing Content-Security-Policy
- Missing X-Frame-Options
- Missing X-Content-Type-Options
- Missing Referrer-Policy

### TLS/SSL
- TLS 1.0 / TLS 1.1 (deprecated)
- Weak cipher suites
- Certificate expiry (90/30/14/7/3/1 day warnings)
- Self-signed certificates
- Weak RSA key size (<2048 bit)
- Invalid certificate chain

### DNS & Email Security
- Missing SPF record
- Missing DMARC record / weak policy (p=none)
- Missing DKIM
- Missing MTA-STS

### Exposures (25+ checks)
- Admin panels (wp-admin, /admin, phpMyAdmin, Adminer)
- Debug pages (Laravel Telescope, Debugbar, Spring Actuator)
- Config files (.env, .git/HEAD, config.php)
- API documentation (Swagger, GraphQL introspection)
- Server information disclosure

---

## License

MIT License — see LICENSE file.

Built with ❤️ using Go, Bubble Tea, lipgloss, and Python.
