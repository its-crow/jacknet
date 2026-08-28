# JackNet

JackNet is a pipx-installable LAN inventory, passive traffic analysis, device-fingerprinting, and local learning CLI. It correlates active discovery with persistent network evidence so a device can accumulate a dossier over time rather than being identified from a single scan.

JackNet currently combines ARP/MAC data, OUI vendor information, PTR hostnames, mDNS/DNS-SD, SSDP/UPnP, Nmap service/OS guesses, passive packet metadata, decoded protocol artifacts, historical observations, user confirmations, network context, and learned fingerprints.

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

## Network identity and IP scope

An IP address is **not** a JackNet device identity and is never treated as globally unique. `192.168.1.19` on one LAN can be an entirely different machine from `192.168.1.19` on another LAN.

JackNet keeps a durable integer `device_id` for each known device and separately records network-scoped address observations:

```text
device_id 12  PlayStation 5
    |
    +-- network 3 / INTERNETS / 192.168.1.0/24 -> 192.168.1.103
    +-- network 7 / another LAN / 192.168.1.0/24 -> 192.168.1.19
```

Network identity is derived from stable local-network context such as gateway identity, subnet, and SSID when available. It does not depend on the JackNet sensor's own NIC, which allows a future Raspberry Pi sensor and the Windows workstation to contribute to the same logical network record.

Inspect the current and previously observed networks:

```powershell
jacknet network
jacknet network --json
```

The network table records a generated network key, CIDR, gateway IP/MAC, SSID, interface metadata, and first/last seen timestamps.

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

`jacknet doctor` reports JackNet-owned state and external capabilities. On Windows this includes Nmap, Wireshark, TShark, dumpcap, Npcap service state, Scapy, Zeroconf, MAC/OUI support, application-data location, database integrity, and platform information.

```powershell
jacknet doctor
jacknet doctor --fix
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

Every stored scan observation receives the current `network_id`. MAC/device identity and network/IP identity are stored separately.

## Passive capture

```powershell
jacknet capture interfaces
jacknet capture probe
jacknet capture diagnose -i 1
jacknet capture live -i 1 --duration 30
```

On Windows JackNet correlates TShark interfaces with `Get-NetAdapter`, so the interface table includes the real adapter description, state, link speed, and MAC address. Each capture session also stores the logical network on which it occurred. Capture-derived traffic observations, artifacts, relationships, endpoints, and addresses carry that network scope.

Analyze an existing capture:

```powershell
jacknet capture analyze sample.pcapng
jacknet capture analyze sample.pcap
```

See [docs/PASSIVE_CAPTURE.md](docs/PASSIVE_CAPTURE.md) for the capture model and troubleshooting notes.

## What JackNet stores from packets

JackNet keeps the original PCAP/PCAPNG capture and can preserve TShark's structured packet decode in the database. It also normalizes useful evidence into queryable artifacts and graph relationships.

Examples include source/destination MAC and IP information, DNS queries and answers, mDNS/DNS-SD names and services, TLS SNI/version/ALPN/certificate metadata when exposed, plaintext HTTP metadata, DHCP/BOOTP hostnames, NBNS/SMB names, SSDP/UPnP data, protocol use, services, and external destinations.

Encrypted HTTPS application payloads remain encrypted unless separate decryption material is explicitly available. JackNet still learns from the surrounding metadata.

## Inspect captured knowledge

```powershell
jacknet evidence 192.168.1.55
jacknet sites 192.168.1.55
jacknet graph 192.168.1.55
jacknet dossier 192.168.1.55
```

IP-based lookups first resolve inside the **currently connected network**. This prevents an address reused on another LAN from silently selecting the wrong device. Dossiers retain address history across multiple networks.

## Reconcile trusted router/admin data

Use `reconcile` when a router, DHCP server, or other trusted source gives you an authoritative current IP/MAC mapping:

```powershell
jacknet reconcile 192.168.1.103 --mac 2e:e1:5d:1d:68:26 --identity "PlayStation 5" --manufacturer Sony --type game_console
```

By default the mapping applies only to the currently detected network. A stored network can be selected explicitly:

```powershell
jacknet reconcile 192.168.1.103 --mac 2e:e1:5d:1d:68:26 --network-id 3
```

Reconciliation removes conflicting ownership of that IP only **within that network**. The same numerical IP on another stored network is untouched.

## Persistent evidence and learning

JackNet is designed around accumulated evidence rather than one-shot guesses. Passive packet features are promoted conservatively: repetition within one capture does not automatically become persistent fingerprint evidence; JackNet considers support across separate capture sessions. Device learning can span networks because a durable device is distinct from the address it happened to receive on a particular LAN.

See [docs/LEARNING.md](docs/LEARNING.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Device confirmation and correction

```powershell
jacknet confirm 192.168.1.55 --yes
jacknet confirm 192.168.1.55 --identity "HP LaserJet M404" --type printer --yes
jacknet confirm 192.168.1.55 --custom-id "Office Printer" --type printer --yes
jacknet correct 192.168.1.55 --identity "Brother HL-L2395DW" --type printer
jacknet learn
jacknet fingerprints
```

Confirmation/correction IP resolution is network-scoped as well.

## Reports and dossiers

```powershell
jacknet scan -A --report -o network.jnet
jacknet dossier 192.168.1.55
jacknet db-report
```

`db-report` shows the current network, current address on that network, total scoped address history, and number of networks on which each device has been observed.

## Health, repair, and backup

```powershell
jacknet doctor
jacknet doctor --fix
jacknet repair
jacknet repair --yes
jacknet backup
jacknet evidence-rebuild
```

`evidence-rebuild` preserves stored network identities and, for network-aware capture sessions, replays each capture into its original network scope.

## Data model

The persistent schema contains `networks`, durable `devices`, network-scoped `device_network_addresses`, observations, labels, extracted features, capture sessions, traffic observations, endpoints, full packet decodes, normalized network artifacts, graph relationships, fingerprints, fingerprint features, hypotheses, and corrections.

The central identity rule is:

```text
IP != device identity
(network_id, IP) = address context
device_id = durable JackNet identity
MAC + evidence + confirmations = identity evidence
```

## Network-wide sensors

A capture performed on an ordinary workstation NIC usually sees that workstation's traffic plus broadcast/multicast traffic; a switched LAN does not normally copy every device's unicast traffic to every port.

JackNet is being structured so additional authorized sensors can feed the same evidence database. Useful future capture points include a Raspberry Pi connected to a mirrored/SPAN port, a Pi acting as an inline bridge/gateway, router capture, a dedicated Wi-Fi monitoring adapter, and remote Wireshark extcap sources such as SSHdump/Wifidump.

Because sensor identity is separate from logical network identity, multiple sensors can eventually observe the same network without creating duplicate LAN records.

## Pipelines / stdin

```powershell
"192.168.1.55" | jacknet scan
Get-Content .\targets.txt | jacknet scan --verbose
jacknet scan -A --man SONY -c 70 --raw
jacknet scan -A --json | ConvertFrom-Json
```
