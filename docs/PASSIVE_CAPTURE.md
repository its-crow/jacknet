# Passive Capture

JackNet's passive-capture path uses Wireshark tooling directly rather than wrapping a second packet-analysis framework around it.

```text
Ethernet / Wi-Fi
      |
   dumpcap / Npcap
      |
    PCAPNG
      |
    TShark
      |
 +----+-------------------+
 |                        |
structured packet decode  normalized evidence
 |                        |
packet_decodes             network_artifacts
                           network_relationships
                           device_features
                           device_endpoints
```

## Windows requirements

For local Windows capture, install:

- Wireshark
- TShark
- dumpcap
- Npcap

`jacknet doctor` reports whether each component is available and where it was found.

JackNet searches the process PATH and the standard Wireshark installation directory. Adding `C:\Program Files\Wireshark` to PATH is also supported.

## Adapter discovery

`jacknet capture interfaces` starts with TShark's capture interfaces, filters out loopback/virtual/extcap sources for normal LAN capture, and then correlates the surviving interface with Windows `Get-NetAdapter` information.

This provides:

- TShark interface ID
- Windows friendly adapter name
- actual hardware/driver description
- link state
- link speed
- MAC address

This correlation matters because TShark interface numbers are temporary and may change after reinstalling Wireshark/Npcap or changing adapters.

## Diagnostics

Run:

```powershell
jacknet capture diagnose -i <ID>
```

The Windows diagnostic checks:

1. Npcap service state.
2. Link-layer types exposed in normal managed mode.
3. Normal managed packet capture.
4. Managed capture with promiscuous mode disabled.
5. Monitor-mode link-layer support.
6. Monitor-mode capture when available.
7. Windows-reported WLAN monitor capability.

A managed Wi-Fi capture does not require monitor mode to see the host's own network traffic. Monitor mode is only required when the adapter/driver must expose raw 802.11 traffic beyond ordinary host traffic.

## Successful capture

```powershell
jacknet capture live -i <ID> --duration 30
```

The live command:

1. captures to PCAPNG,
2. performs the existing structured ingestion,
3. runs a full TShark decode,
4. stores raw structured packet data,
5. extracts normalized artifacts,
6. updates graph relationships,
7. links evidence to known devices when possible,
8. runs the fingerprint learner.

A zero-packet capture is considered a failure. JackNet does not silently substitute loopback capture or report success when the selected physical interface produced no traffic.

## What can be learned

Passive observation can reveal:

- IP/MAC relationships
- DNS activity
- mDNS/DNS-SD identities and services
- DHCP hostnames
- SSDP/UPnP advertising
- SMB/NBNS naming
- TLS SNI and handshake metadata
- plaintext HTTP metadata
- protocol usage
- external destinations
- recurring timing and behavior patterns

HTTPS payloads are normally encrypted. JackNet can still observe metadata such as destination IPs, DNS lookups, TLS SNI when exposed, timing, byte counts, and protocol behavior.

## Network-wide visibility

A normal workstation NIC on a switched network is not automatically a full-network tap. It generally sees:

- traffic to/from that workstation
- broadcast traffic
- multicast traffic
- traffic the switch/AP deliberately forwards to it

For network-wide passive observation, use an authorized capture point such as a mirrored/SPAN port, inline bridge, router capture facility, or dedicated monitoring sensor.

## Raspberry Pi sensor direction

A Raspberry Pi 5 is a good future JackNet sensor platform. Potential modes include:

- remote `dumpcap`/`tcpdump` over SSH
- mirrored-port sensor
- inline bridge/gateway
- dedicated Wi-Fi capture sensor with a compatible adapter

The sensor should emit captures/evidence into the same JackNet database model so identities and behavior accumulate regardless of where packets were observed.
