# JackNet

JackNet is a pipx-installable LAN inventory, passive traffic analysis, device-fingerprinting, and local learning CLI. It correlates active discovery with persistent network evidence so a device can accumulate a dossier over time rather than being identified from a single scan.

JackNet currently combines ARP/MAC data, OUI vendor information, PTR hostnames, mDNS/DNS-SD, SSDP/UPnP, Nmap service/OS guesses, passive packet metadata, decoded protocol artifacts, historical observations, user confirmations, and learned fingerprints.

## Install

Requires Python 3.11+. Nmap is optional but strongly recommended. Passive capture on Windows uses Wireshark/TShark, dumpcap, and Npcap.

```powershell
pipx install .
jacknet init
jacknet doctor
```

During development from a local checkout:

```powershell
git pull
pipx install . --force
```

## First-time initialization

Default app data lives in `~/.jacknet` unless another directory is selected:

```powershell
jacknet init
jacknet init --data-dir D:\JackNetData
```

JackNet stores its database, reports, backups, cache, logs, exports, learned fingerprints, and capture-derived evidence under the configured data directory. The location pointer is stored in `~/.config/jacknet/config.json`. `JACKNET_DATA_DIR` can temporarily override it.

Change it later:

```powershell
jacknet config --data-dir D:\NetworkTools\JackNet
```

## Doctor

`jacknet doctor` reports JackNet-owned state and external capabilities. On Windows this includes:

- Nmap
- Wireshark
- TShark
- dumpcap
- Npcap service state
- Scapy
- Zeroconf
- MAC/OUI support
- application data location
- database integrity
- platform information

```powershell
jacknet doctor
jacknet doctor --fix
```

`--fix` only repairs JackNet-owned state such as application directories and database migrations. It does not silently modify external software.

## Scanning

```powershell
jacknet scan -A
jacknet scan -A --verbose
jacknet scan -A --deep
jacknet scan --ip 192.168.1.55 --verbose
jacknet scan -A --man SONY --confidence 70
jacknet scan -A --type game_console
```

Active scans feed the same persistent device database used by passive capture.

## Passive capture

List only real Ethernet/Wi-Fi adapters exposed by TShark:

```powershell
jacknet capture interfaces
```

On Windows JackNet correlates TShark interfaces with `Get-NetAdapter`, so the table includes the real adapter description, state, link speed, and MAC address. Active adapters are shown first.

Probe capture interfaces:

```powershell
jacknet capture probe
```

Diagnose one interface in detail:

```powershell
jacknet capture diagnose -i 1
```

The diagnostic checks Npcap service state, managed capture, managed capture without promiscuous mode, available link-layer types, and monitor-mode support.

Capture and immediately ingest traffic:

```powershell
jacknet capture live -i 1 --duration 30
```

Typical successful output reports:

- packets captured
- full packet decodes stored
- normalized artifacts extracted
- graph relationships created/updated
- devices linked
- capture file path
- fingerprints promoted by the learner

Analyze an existing capture instead:

```powershell
jacknet capture analyze sample.pcapng
jacknet capture analyze sample.pcap
```

See [docs/PASSIVE_CAPTURE.md](docs/PASSIVE_CAPTURE.md) for the capture model and troubleshooting notes.

## What JackNet stores from packets

JackNet keeps the original PCAP/PCAPNG capture and can preserve TShark's structured packet decode in the database. It also normalizes useful evidence into queryable artifacts and graph relationships.

Examples include:

- source/destination MAC and IP information
- DNS queries and answers
- mDNS/DNS-SD names and services
- TLS SNI, versions, ALPN, and certificate-derived metadata when exposed
- HTTP host, method, URI, user agent, referrer, and content type when plaintext
- DHCP/BOOTP hostnames
- NBNS/SMB names
- SSDP/UPnP server and USN data
- observed protocols and services
- external destinations and device-to-destination relationships

Encrypted HTTPS application payloads remain encrypted unless separate decryption material is explicitly available. JackNet still learns from the surrounding metadata.

## Persistent evidence and learning

JackNet is designed around accumulated evidence rather than one-shot guesses:

```text
active scans ───────────┐
                       │
packet captures ────────┼──> persistent device dossiers
                       │          │
user confirmations ────┘          ├── features
                                  ├── endpoints
                                  ├── protocol behavior
                                  ├── relationships
                                  └── identity hypotheses
                                           │
                                           v
                                      fingerprint learner
```

A confirmed or repeatedly supported identity can teach reusable fingerprints. The goal is for JackNet to become more useful as it observes the same network over time while preserving the evidence behind each conclusion.

See [docs/LEARNING.md](docs/LEARNING.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Device confirmation and correction

Confirm JackNet's current identification:

```powershell
jacknet confirm 192.168.1.55 --yes
```

Supply your own identity or custom name:

```powershell
jacknet confirm 192.168.1.55 --identity "HP LaserJet M404" --type printer --yes
jacknet confirm 192.168.1.55 --custom-id "Office Printer" --type printer --yes
```

Correct an existing identification:

```powershell
jacknet correct 192.168.1.55 --identity "Brother HL-L2395DW" --type printer
```

Inspect learned fingerprints:

```powershell
jacknet learn
jacknet fingerprints
```

## Reports and dossiers

```powershell
jacknet scan -A --report -o network.jnet
jacknet scan -A --report --format json -o network.json
jacknet scan -A --report --format html -o network.html
jacknet dossier 192.168.1.55
jacknet db-report
```

Supported scan-report formats include `jnet`, `json`, `txt`, `csv`, and `html`.

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

- recreates missing JackNet-owned directories
- creates a missing database and applies schema migrations
- reruns idempotent migrations when the database is healthy
- never silently destroys a corrupt database
- preserves damaged databases before creating a clean replacement when explicitly authorized
- reports external dependency problems instead of modifying unrelated software behind the user's back

## Data model

The persistent schema contains devices, addresses, observations, labels, extracted features, capture sessions, traffic observations, endpoints, full packet decodes, normalized network artifacts, graph relationships, fingerprints, fingerprint features, hypotheses, and corrections.

Raw observations are intentionally retained so newer fingerprint engines can re-evaluate older evidence.

## Network-wide sensors

A capture performed on an ordinary workstation NIC usually sees that workstation's traffic plus broadcast/multicast traffic; a switched LAN does not normally copy every device's unicast traffic to every port.

JackNet is being structured so additional sensors can later feed the same evidence database. Useful future capture points include:

- a Raspberry Pi connected to a mirrored/SPAN switch port
- a Pi acting as an inline bridge/gateway
- a router capable of remote dumpcap/tcpdump capture
- a dedicated Wi-Fi monitoring adapter
- remote Wireshark extcap sources such as SSHdump/Wifidump

The long-term model is one JackNet knowledge base receiving evidence from multiple authorized sensors.

## Pipelines / stdin

JackNet accepts IP addresses, hostnames, and CIDRs from stdin. Redirected stdin is detected automatically.

```powershell
"192.168.1.55" | jacknet scan
"192.168.1.55", "192.168.1.72" | jacknet scan --deep
Get-Content .\targets.txt | jacknet scan --verbose
"192.168.1.0/28" | jacknet scan --no-nmap
```

Pipeline-friendly output:

```powershell
jacknet scan -A --man SONY -c 70 --raw
jacknet scan -A --json | ConvertFrom-Json
```

`--raw` writes only matching IP addresses to stdout. `--json` emits plain JSON to stdout.
