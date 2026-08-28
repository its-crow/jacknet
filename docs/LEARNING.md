# JackNet Learning

JackNet's learner should improve from accumulated evidence without confusing repetition with certainty.

## Inputs

The learner can use:

- confirmed identities and corrections
- manufacturer/OUI information
- hostnames and hostname prefixes
- open ports and discovered services
- DNS/mDNS names
- TLS SNI
- HTTP host information
- SSDP/UPnP metadata
- protocol/service usage
- recurring endpoints
- timing and behavioral patterns

## Ground truth

User confirmations are the strongest local training examples. A correction should not merely overwrite the current display; it should remain as explicit historical training data so future fingerprints can learn the replacement.

## Promotion model

A candidate fingerprint should be promoted only when there is enough support to justify reuse. Useful criteria include:

- multiple observations across time
- multiple devices/examples when available
- high precision against known examples
- user-backed ground truth
- several independent feature types

Repeated packets from one capture should not by themselves turn a weak feature into a strong fingerprint.

## Persistent behavior

Passive evidence becomes useful when it survives the individual capture. For example, if a device repeatedly contacts the same service or advertises the same mDNS identity, JackNet should retain that as a persistent feature and make it available to later scans even when the current scan does not observe the traffic again.

This is important because active discovery and passive capture happen at different times. The learner should reason over the device dossier, not only the evidence present in the current command invocation.

## Contradictions

Learning must preserve contradictory evidence. A new observation should not silently erase an older fact. Instead JackNet should be able to record that:

- a feature stopped appearing,
- an address moved to another device,
- a previous hypothesis was corrected,
- a learned fingerprint produced a false positive.

These are inputs to confidence calibration.

## Future behavioral fingerprints

Once enough traffic history exists, JackNet can derive higher-level features such as:

- recurring destination sets
- protocol combinations
- service-advertisement combinations
- time-of-day activity
- packet-size/flow-shape summaries
- DNS/service naming families
- stable vendor-specific cloud endpoints

These should remain explainable. A report should be able to show which evidence caused an identity hypothesis or anomaly score.
