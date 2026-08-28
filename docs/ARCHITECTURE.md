# JackNet Architecture

JackNet is designed as a persistent network knowledge engine rather than a one-shot scanner.

## Evidence flow

```text
active discovery ─┐
                  ├──> device identity + evidence store ───> learner
passive capture ──┤                                   │
                  │                                   ├──> dossiers
user correction ──┘                                   ├──> graph
                                                      └──> reports
```

## Core data layers

### Devices

A device is the long-lived entity JackNet tries to follow over time. MAC address is the strongest ordinary LAN identifier when available. IP addresses are historical properties of a device, not the identity itself.

### Observations

Observations preserve what JackNet saw at a particular moment. They are intentionally retained so future algorithms can reconsider old evidence.

### Capture sessions

Each imported or live capture is tracked as a session with source information and capture metadata.

### Traffic observations

Compact per-packet/per-flow observations support traffic accounting and protocol summaries.

### Packet decodes

`packet_decodes` preserves TShark's structured decode for a packet. This is the reprocessing layer: later JackNet versions can derive new features without requiring the original parser logic to have existed at capture time.

### Network artifacts

`network_artifacts` stores normalized facts such as domains, hostnames, TLS SNI, HTTP metadata, protocol names, and service names.

### Relationships

`network_relationships` is the graph-ready layer. Example relationships include:

```text
device -> CONTACTS -> domain
device -> CONNECTS_TO -> IP
device -> USES -> protocol
device -> USES -> service
device -> HAS_IP -> address
```

Relationships retain first-seen, last-seen, and hit counts so behavior can be ranked by persistence instead of presence alone.

### Device features

Repeated evidence can be promoted into persistent device features. These features are inputs to the identity/fingerprint learner.

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

Useful dimensions include:

- source reliability
- repetition over time
- number of independent evidence types
- user confirmation
- fingerprint precision
- contradictions
- recency

## Sensor model

The database model should not assume packets came from the local Windows host. Future sensors can include:

- local Npcap capture
- Raspberry Pi
- router capture
- mirrored switch port
- remote SSHdump/Wifidump source

Every observation should retain enough source metadata to answer not just "what did JackNet see?" but also "where did JackNet see it?"
