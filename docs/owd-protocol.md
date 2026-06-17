# OWD Measurement Protocol — Reference

## Overview

The OWD Measurement Protocol is a custom application-layer protocol
used by MoonGen in the TU Dresden 5G Campus Networks dataset to embed
hardware-synchronized transmit timestamps into UDP measurement packets.

It is not an IETF standard — it is specific to this dataset.

## Packet Structure — End-to-End Captures
Ethernet (14 B)

└── IPv4 (20 B)

└── UDP (8 B)  src=1337, dst=65001

└── OWD Payload (20 B)

├── TS Seconds    [0:8]   uint64 big-endian

├── TS Nanoseconds[8:16]  uint64 big-endian

└── Sequence No   [16:20] uint32 big-endian

## Packet Structure — Core Network Captures
Ethernet (14 B)

└── IPv4 (20 B)

└── UDP (8 B)  src=any, dst=2152  (GTP-U)

└── GTP-U Header (8 B minimum)

├── Optional Extension Headers (variable)

│   └── PDU Session Container (if present)

└── Inner IPv4 (20 B)

└── Inner UDP (8 B)  src=1337, dst=65001

└── OWD Payload (20 B)  ← same as above

## Timestamp Precision

- Resolution: nanoseconds
- Clock source: PTP (IEEE 1588) hardware synchronization via MoonGen
- Epoch: Unix epoch (seconds since 1970-01-01 00:00:00 UTC)
- Byte order: big-endian (network byte order)

## GTP-U Extension Header Handling

GTP-U extension headers are variable length. The parser reads the
extension header type byte and length byte, then skips the header
(length field × 4 bytes total including the length and next-type bytes).
This continues until the Next Extension Header Type field is 0x00
(no more extension headers).

## Known Characteristics of the Dataset

- Packet sizes used: 128, 256, 512, 1024, 1280 bytes
- Packet rates used: 10, 100, 1000 pps (varies by capture file)
- Mean OWD observed: 5.0–8.1 ms depending on packet rate
- OWD range observed: 3.66–18.87 ms across all captures
- Clock synchronization accuracy: sub-microsecond (PTP hardware)