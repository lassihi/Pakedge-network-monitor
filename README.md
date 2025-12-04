# Pakedge Network Monitor

Monitor and log network activity from a Pakedge router UI. The app scrapes leases, static devices and live connection data, saves it to a SQLite database, and raises alerts for network scans and new MAC addresses.

## Features
- Scrapes Pakedge router UI for:
	- Active DHCP leases
	- Static devices
	- Live connections
- Normalizes and stores information in SQLite (`network.db`).
- Alerts:
	- Connect scan detection (multiple distinct targets)
	- New MAC addresses (vs. known static/lease set)
- A seperate interactive console with readable output:
	- `alerts`, `devices`, `leases`, `connections <ip>`, `schema`, `SELECT ...`
- Docker and Compose support

## Requirements
- Python 3.11+
- Pakedge router reachable and credentials set via environment variables.
- Dependencies listed in `requirements.txt` (PyYAML, requests, bs4, etc.).

## Configuration
The app reads `config.yaml` from `src/pakedge-monitor/config.yaml` by default. Example keys:

```yaml
router_url: "https://your-router"
alert_detection_interval_seconds: 10
database_update_interval_seconds: 60
alert_on_connect_scans: True
alert_on_new_devices: True
targets:
  - !!python/tuple["192.168.1.10", 80, 1]
  - !!python/tuple["192.168.1.20", 443, 3]
```

Runtime environment variables:
- `PAKEDGE_USER`: Router UI username
- `PAKEDGE_PASS`: Router UI password
- `PAKEDGE_DB` (optional): Override SQLite database path.

## Usage

### Docker Compose (recommended)

Commands:

```bash
# Main app
PAKEDGE_USER="router-username" PAKEDGE_PASS="router-password" docker compose up -d --build

# Console
docker compose run --rm -it pakedge python src/pakedge-monitor/console_app.py

# Updating code
git pull
PAKEDGE_USER="router-username" PAKEDGE_PASS="router-password" docker compose up -d --force-recreate
```

### Running Locally (without Docker)
Install deps and run:

```bash
cd /path/to/Pakedge-network-monitor/
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export PAKEDGE_USER="router-username"
export PAKEDGE_PASS="router-password"

python src/pakedge-monitor/main.py

# Console
python src/pakedge-monitor/console_app.py
```
