# OWD Wireshark Dissector

A Wireshark Lua dissector and Python PCAP parser for the One-Way Delay (OWD)
Measurement Protocol used in the IEEE DataPort 5G Campus Networks dataset
published by Rischke et al. (TU Dresden, 2021).

## Background

The TU Dresden dataset captures real traffic from a deployed 5G Standalone
testbed using MoonGen — a hardware traffic generator that embeds a
nanosecond-precision transmit timestamp into each measurement packet's UDP
payload using a custom protocol. Wireshark has no built-in dissector for
this protocol — the payload shows as raw bytes. This repo provides:

1. A Lua dissector that teaches Wireshark to parse the OWD payload,
   displaying TX timestamp, sequence number, and computed one-way delay
   directly in the packet detail pane.
2. A Python parser that extracts all OWD measurements from PCAP files
   into a structured CSV, including GTP-U tunnel unwrapping for core
   network captures.

## OWD Measurement Protocol — Payload Layout

Each UDP measurement packet (src port 1337, dst port 65001) carries a
20-byte payload after the UDP header:

| Offset | Size | Type             | Field                          |
|--------|------|------------------|--------------------------------|
| 0      | 8 B  | uint64 big-endian| TX Timestamp — seconds         |
| 8      | 8 B  | uint64 big-endian| TX Timestamp — nanoseconds     |
| 16     | 4 B  | uint32 big-endian| Sequence Number                |

For core network captures (GTP-U tunnel on UDP port 2152), the measurement
packet is wrapped inside a GTP-U tunnel. Both tools handle this automatically.

One-way delay:
  OWD (ms) = (T_RX − T_TX) × 1000
where T_RX is the PCAP per-packet header timestamp and T_TX is the embedded
payload timestamp — both synchronized via PTP hardware clocks.

## Repository Structure
owd-wireshark-dissector/

├── dissector/

│   └── owd_dissector.lua      Wireshark Lua dissector

├── parser/

│   ├── parse_pcaps.py         Python PCAP → CSV parser

│   └── README.md              Parser usage

├── docs/

│   └── owd_protocol.md        Protocol byte layout reference

├── sample_output/

│   └── README.md              Where to get sample PCAPs

└── README.md

## Quick Start — Wireshark Dissector

Requirements: Wireshark 3.0 or later.

Install the dissector:

```bash
# Linux / macOS
cp dissector/owd_dissector.lua ~/.config/wireshark/plugins/

# Windows
copy dissector\owd_dissector.lua %APPDATA%\Wireshark\plugins\
```

Restart Wireshark. Open a PCAP from the TU Dresden dataset.
Filter: `udp.port == 1337 or udp.port == 65001`

You will see a new "OWD Measurement Protocol" section in the packet
detail pane showing TX timestamp, sequence number, and computed OWD.

## Quick Start — Python Parser

Requirements: Python 3.8+, no external libraries.

```bash
cd parser
python parse_pcaps.py --input /path/to/pcaps/ --output owd_dataset.csv
```

Output CSV columns: packet_size_bytes, packet_rate_pps, seq_no,
sent_ts, recv_ts, owd_ms, jitter_ms, network_type, direction, capture_type.

## Dataset

This tool is designed for the IEEE DataPort 5G Campus Networks dataset:

J. Rischke, P. Sossalla, S. Itting, F. H. P. Fitzek, and M. Reisslein,
"5G Campus Networks: A First Measurement Study," IEEE Access, vol. 9,
pp. 121786–121803, 2021. DOI: 10.1109/ACCESS.2021.3108423

Download (free, IEEE DataPort account required):
https://ieee-dataport.org/open-access/5g-campus-networks-measurement-dataset

## Related Work

Developed as part of a B.Tech minor project on ML-based delay and jitter
prediction for QoS traffic in 5G campus networks (SRM IST, 2026).
Results on the extracted dataset:
- Delay: MAE 0.117 ms, R² 0.90 (Random Forest)
- Jitter: MAE 0.103 ms, R² 0.88 (Random Forest)

## License

MIT — see LICENSE.

## Authors

Shubh Agarwal — github.com/ShubhCodes21
Vidushi Mishra — github.com/vidushimishra11d-cmyk
SRM Institute of Science and Technology, 2026