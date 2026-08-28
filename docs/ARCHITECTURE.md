# JackNet Architecture

JackNet is designed as a persistent network knowledge engine rather than a one-shot scanner.

## Evidence flow

```text
active discovery ─┐
                  ├──> network scope + device identity + evidence store ───> learner
passive capture ──┤                                              │
                  │                                              ├──> dossiers
user correction ──┘                                              ├──> graph
                                                                 └──> reports
```

## Identity hierarchy

JackNet deliberately separates four different concepts:

```text
logical network
    |
    +-- device
          |
          +-- network-scoped address
          +-- observations
          +-- behavior/evidence
```

The core rule is:

```text
IP address != device identity
(network_id, IP) = address context
device_id = durable JackNet entity
```

An address such as `192.168.1.19` can legitimately refer to different devices on two different networks. It can also be reassigned by DHCP on the same network over time. Therefore no IP address is used as a primary key.

## Core data layers

### Networks

`networks` stores the logical LAN/WLAN context in which evidence was observed. A stable `network_key` is derived from available gateway/L2 identity, subnet, and SSID information. The current sensor NIC is intentionally not part of the logical network key so multiple JackNet sensors can later contribute to the same network.

Stored network metadata includes:

- generated `network_id`
- stable `network_key`
- display name
- CIDR/subnet
- gateway IP
- gateway MAC
- SSID when available
- observing interface metadata
- first/last seen

### Devices

A device is the long-lived entity JackNet tries to follow over time. `device_id` is the database primary key. A MAC address is strong ordinary LAN evidence when available, but JackNet also records whether it is globally assigned or locally administered/private.

A device may be observed on multiple networks and may have different addresses on each one.

### Network-scoped addresses

`device_network_addresses` maps:

```text
network_id + device_id + IP
```

and records first seen, last seen, source, and observation count. IP ownership repair/reconciliation only affects the selected network, never every occurrence of that numerical IP in the database.

### Observations

Observations preserve what JackNet saw at a particular moment. New observations carry `network_id` so a repeated private address cannot be confused across networks.

### Capture sessions

Each imported or live capture is tracked as a session with source information, capture metadata, and `network_id`. Reprocessing can therefore return retained captures to the network on which they were originally observed.

### Traffic observations

Compact per-packet/per-flow observations support traffic accounting and protocol summaries and carry the capture's network scope.

### Packet decodes

`packet_decodes` preserves TShark's structured decode for a packet. The containing capture session provides its network scope.

### Network artifacts

`network_artifacts` stores normalized facts such as domains, hostnames, TLS SNI, HTTP metadata, protocol names, and service names. Artifacts retain `network_id` in addition to device/session ownership.

### Relationships

`network_relationships` is the graph-ready layer. Example relationships include:

```text
device -> CONTACTS -> domain
device -> CONNECTS_TO -> IP
device -> USES -> protocol
device -> USES -> service
device -> HAS_ADDRESS_ON -> network/IP
```

Relationships retain network scope, first-seen, last-seen, and hit counts.

### Device features

Repeated evidence can be promoted into persistent device features. Device-level learning may combine evidence across networks because the learned subject is the durable device, not a temporary address.

## IP resolution rules

When a command receives only an IP address, JackNet should resolve it in this order:

1. Current logical network.
2. Explicit `--network-id`, when supported.
3. A unique unambiguous historical match.
4. Refuse/flag ambiguity rather than silently selecting the wrong device.

Known MAC/device identity always outranks an IP-only association.

## Reconciliation

Trusted router/DHCP/admin data is a network-scoped correction. For example:

```text
network 3 + 192.168.1.103 -> device 12 / MAC 2e:e1:5d:1d:68:26
```

A conflicting mapping for `192.168.1.103` on network 7 is unrelated and must not be touched.

## Identity principles

JackNet should distinguish:

1. **Observed fact** — directly measured data.
2. **Derived feature** — normalized or aggregated evidence.
3. **Hypothesis** — a possible identity or device type.
4. **Confirmed identity** — user-backed ground truth.
5. **Learned fingerprint** — reusable evidence pattern learned from repeated/confirmed examples.

The UI should not present a hypothesis as a fact merely because it has a high score.

## Confidence

Confidence should increase from independent, repeatable evidence rather than raw packet volume alone. Ten thousand copies of one weak signal should not outweigh several independent strong signals.

Useful dimensions include source reliability, repetition over time, independent evidence types, user confirmation, fingerprint precision, contradictions, recency, and cross-network consistency.

## Sensor model

The database model should not assume packets came from the local Windows host. Future sensors can include local Npcap capture, Raspberry Pi, router capture, mirrored switch ports, and remote SSHdump/Wifidump sources.

Sensor identity and logical network identity are separate concepts. A Windows workstation and Raspberry Pi observing the same LAN should contribute evidence to the same `network_id`, while one sensor moved to a different LAN should create/use a different logical network record.
