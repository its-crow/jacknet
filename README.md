# Jacknet

## What we are building

Jacknet is a network-observation and device-intelligence tool.

The goal is not to rewrite Nmap, Wireshark, TShark, or other mature networking tools. Jacknet will use them as sensors, combine what they discover, remember it over time, and explain what it knows about each device on the network.

The central idea is simple:

> A device is more than its current IP address.

An IP can change. Jacknet should build a persistent dossier from MAC addresses, address history, hostnames, manufacturers, services, protocols, DNS activity, traffic patterns, discovery protocols, and other evidence.

## The architecture

```text
                       JACKNET
                          |
          +---------------+---------------+
          |               |               |
        Nmap          PCAP/TShark      LAN discovery
     active scans     passive traffic   ARP/mDNS/SSDP
          |               |               |
          +---------------+---------------+
                          |
                    evidence store
                          |
                    device identity
                          |
               +----------+----------+
               |                     |
             history               behavior
```

Jacknet's job is correlation and memory.

Nmap is good at actively asking a machine what is exposed. Packet captures are good at showing what machines actually do. ARP, DHCP, DNS, mDNS, SSDP and similar protocols provide identity clues. None of these sources alone tells the whole story.

Jacknet will join those clues together.

## Rule #1: evidence before conclusions

Jacknet should never simply say:

```text
This is an Xbox. Confidence: 97%
```

It should be able to explain why:

```text
Likely device: Xbox Series X
Confidence: 97%

Evidence:
  MAC vendor       Microsoft
  DHCP hostname    Xbox
  DNS activity     Xbox/Microsoft services
  UDP service      3074 observed
  Nmap evidence    matching services
  First seen       2026-09-04
  Last seen        12 seconds ago
```

Every conclusion should be traceable back to observations.

## Rule #2: observations are history, not disposable scan results

A scan should not overwrite what Jacknet knew yesterday.

Jacknet should remember observations with timestamps and sources.

For example:

```text
DEVICE 17
  MAC/interface
    address history
      192.168.0.37   previous
      192.168.0.42   current

  evidence
    Nmap
    ARP
    DHCP
    DNS
    mDNS
    SSDP
    TLS
    PCAP
```

This lets Jacknet learn a device even when DHCP changes its address.

## Rule #3: use the best existing tools

We do not need to reinvent packet decoding or port scanning.

Recommended components:

- **Python** — Jacknet itself.
- **SQLite** — persistent local evidence/history database.
- **Nmap XML** — active host, port, service and OS evidence.
- **TShark** — Wireshark's dissector engine for extracting protocol information from captures.
- **dumpcap** — lightweight packet capture when Jacknet performs live capture.
- **pcap/pcapng** — standard capture files Jacknet can ingest.
- **Zeek later** — higher-level connection and behavioral metadata once the foundation works.

Jacknet orchestrates these tools and turns their output into one model of the network.

## Development roadmap

### Phase 1 — Foundation

Build the smallest real Jacknet.

1. Python package with a clean `src/` layout.
2. Pipx-installable `jacknet` command.
3. Configuration and application-data directory.
4. SQLite database.
5. A device/evidence data model designed before scanners are added.
6. Commands to initialize and inspect the database.

The important part of Phase 1 is getting identity and evidence storage right. Everything later depends on it.

### Phase 2 — Active discovery with Nmap

Add Nmap as the first sensor.

Jacknet will execute Nmap and consume its XML output rather than scraping terminal text.

We want to learn:

- IP addresses
- MAC addresses when available
- manufacturers/OUI
- open ports
- detected services
- service versions
- OS guesses
- hostnames
- scan timestamps

All results become evidence in the database.

### Phase 3 — Local discovery protocols

Add observations from protocols that reveal devices naturally on a LAN:

- ARP
- reverse DNS
- mDNS/DNS-SD
- SSDP/UPnP

These often reveal information that a port scan cannot.

### Phase 4 — PCAP ingestion

Make packet captures a first-class Jacknet input.

```bash
jacknet ingest traffic.pcapng
```

Jacknet will use TShark to extract useful observations such as:

- IP/MAC relationships
- DNS queries
- protocols used
- remote endpoints
- ports
- traffic volumes
- DHCP information
- TLS metadata that is legitimately visible without decrypting payloads
- timing and connection patterns

The raw capture remains the source; Jacknet stores useful structured observations from it.

### Phase 5 — Device dossiers

Bring all evidence together.

Example command:

```bash
jacknet explain 192.168.0.42
```

The result should show:

- what Jacknet thinks the device is
- confidence
- why it thinks that
- current and historical addresses
- services
- protocols
- domains/endpoints it normally contacts
- first/last seen
- evidence sources
- user-confirmed identity, if one exists

A user's confirmation should be strong evidence, but we should preserve the observations that led to it.

### Phase 6 — Live passive monitoring

When we have a managed switch with port mirroring, a Raspberry Pi can become a passive Jacknet sensor.

```text
Internet
   |
router
   |
managed switch
   |              \
network devices    mirrored traffic
                         |
                     Raspberry Pi
                         |
                 dumpcap / Jacknet
```

The Pi does not need to interfere with traffic. The switch sends it copies of packets to observe.

Jacknet can continuously ingest those observations into the same database used by active scans.

### Phase 7 — Behavior baselines

Only after Jacknet has reliable historical data should we attempt anomaly detection.

For each device, learn things such as:

- usual protocols
- usual services
- common domains/endpoints
- typical traffic volume
- normal active hours
- normal open ports
- expected peers

Then Jacknet can flag changes rather than blindly labeling traffic malicious.

Example:

```text
BEHAVIOR CHANGE

Device: Xbox Series X

New observations:
  TCP/22 now listening
  previously unseen destination
  sustained unusual outbound traffic

Reason for alert:
  these differ significantly from this device's history
```

The alert must show the evidence that caused it.

### Phase 8 — Zeek and richer network intelligence

Once PCAP ingestion and identity correlation are solid, evaluate Zeek as another sensor.

Zeek can convert packet traffic into structured connection/activity records. Jacknet can correlate those records with the same device dossiers instead of duplicating Zeek's job.

### Phase 9 — Reporting

Jacknet should eventually answer useful questions directly:

```bash
jacknet devices
jacknet explain <ip|mac|device-id>
jacknet history <device>
jacknet changes
jacknet traffic <device>
jacknet report
```

Reports should be readable by a human but backed by structured evidence.

## What Jacknet is NOT

Jacknet is not intended to:

- replace Wireshark
- replace Nmap
- decrypt traffic it does not have keys for
- perform ARP spoofing just to obtain visibility
- claim certainty without evidence
- call every unusual event an attack
- hide its reasoning behind an unexplained "AI" score

## Security philosophy

Jacknet should prefer passive observation and normal administrative access to the network.

Our own network is the laboratory. We can learn Ethernet, ARP, IP, TCP/UDP, DNS, DHCP, TLS, routing, NAT, VPNs, packet capture, service discovery and network monitoring by implementing each Jacknet sensor and examining the actual evidence it produces.

The project should teach us what the network is doing rather than merely produce colorful output.

## Recommended first milestone

Do **not** start with Nmap or Wireshark yet.

First design the evidence model.

We need to answer these questions correctly:

1. What is a device?
2. What is an interface?
3. What is an address?
4. What is an observation?
5. How do we record where an observation came from?
6. How do observations expire without deleting history?
7. How do we express confidence?
8. How does a user confirm or correct an identity?

Once those answers are represented cleanly in SQLite, Nmap becomes just the first source feeding evidence into it, and PCAP becomes another.

That is where the new Jacknet should begin.
