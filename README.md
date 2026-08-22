# JackNet

JackNet is a pipx-installable LAN inventory and device-fingerprinting CLI. It correlates ARP/MAC, OUI vendor data, PTR hostnames, mDNS/DNS-SD, SSDP/UPnP, Nmap services/OS guesses, and local historical evidence.

## Install

Requires Python 3.11+. Nmap is optional but strongly recommended for deeper service/OS fingerprinting.

```powershell
pipx install .
jacknet init
jacknet doctor
```

Install directly from an unpacked release directory with `pipx install .`, or from a built wheel with `pipx install dist/jacknet-*.whl`.

## First-time initialization

Default app data lives in `~/.jacknet`:

```powershell
jacknet init
```

Choose the application-data directory yourself:

```powershell
jacknet init --data-dir D:\JackNetData
```

JackNet stores its database, reports, backups, cache, logs, exports, and learned fingerprints under that directory. The small location pointer is stored separately in `~/.config/jacknet/config.json`. `JACKNET_DATA_DIR` can temporarily override it.

Change it later:

```powershell
jacknet config --data-dir D:\NetworkTools\JackNet
```

## Scanning

```powershell
jacknet scan -A
jacknet scan -A --verbose
jacknet scan -A --deep
jacknet scan --ip 192.168.1.55 --verbose
jacknet scan -A --man SONY --confidence 70
jacknet scan -A --type game_console
```

## Reports

```powershell
jacknet scan -A --report -o network.jnet
jacknet scan -A --report --format json -o network.json
jacknet scan -A --report --format html -o network.html
```

Supported report formats: `jnet`, `json`, `txt`, `csv`, `html`.

## Knowledge and history

```powershell
jacknet manual
jacknet manual --search playstation
jacknet history --limit 100
```

## Health, repair, and backup

```powershell
jacknet doctor
jacknet doctor --fix
jacknet repair
jacknet repair --yes
jacknet backup
jacknet backup -o D:\Backups\jacknet.db
```

Safe repair behavior:

- Recreates missing JackNet-owned directories.
- Creates a missing database and applies schema migrations.
- Reruns idempotent migrations when the database is healthy.
- Never silently destroys a corrupt database.
- `repair --yes` renames a corrupt DB to a timestamped `.corrupt-*.db` file and creates a clean schema.
- External requirements such as Nmap are reported as user actions rather than modified behind your back.

## Data model

The current schema includes persistent devices, observations, labels, extracted features, fingerprints, fingerprint features, hypotheses, and corrections. Raw observation payloads are retained so future fingerprint engines can re-evaluate historical scans.

## Pipelines / stdin

JackNet accepts IP addresses, hostnames, and CIDRs from stdin. Redirected stdin is detected automatically; `--stdin` is available when explicit behavior is preferred.

```powershell
"192.168.1.55" | jacknet scan
"192.168.1.55", "192.168.1.72" | jacknet scan --deep
Get-Content .\\targets.txt | jacknet scan --verbose
"192.168.1.0/28" | jacknet scan --no-nmap
```

Pipeline-friendly output:

```powershell
jacknet scan -A --man SONY -c 70 --raw
jacknet scan -A --json | ConvertFrom-Json
```

`--raw` writes only matching IP addresses to stdout. `--json` emits plain JSON to stdout, making both suitable for redirection and composition.
