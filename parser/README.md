# Parser — Usage Guide

## What it does

Reads binary PCAP files from the TU Dresden 5G Campus Networks dataset
and extracts per-packet one-way delay measurements into a CSV.

Handles:
- End-to-end captures (UDP port 1337 → 65001)
- Core network captures (GTP-U tunnel on UDP port 2152, with extension
  header support including PDU Session Container)

No external libraries required — uses only Python's standard `struct`
and `os` modules.

## Usage

```bash
python parse_pcaps.py --input /path/to/pcap/folder/ --output results.csv
```

The script infers packet size and packet rate from the filename convention
used in the TU Dresden dataset:
  `{size}.{rate}.pcap`       e.g. 128.100.pcap  → 128 B, 100 pps
  `{size}.{rate}.core.pcap`  e.g. 256.1000.core.pcap → 256 B, 1000 pps

## How OWD is computed

Each measurement packet carries a 20-byte payload embedding the TX
timestamp from MoonGen's PTP-synchronized hardware clock:

```python
ts_sec  = struct.unpack('>Q', payload[0:8])[0]
ts_nano = struct.unpack('>Q', payload[8:16])[0]
seq_no  = struct.unpack('>I', payload[16:20])[0]

T_TX = ts_sec + ts_nano * 1e-9
OWD  = T_RX - T_TX          # T_RX from PCAP per-packet header
```

This is equivalent to `ntohl()`/`ntohll()` byte-order conversion in C —
the payload uses network byte order (big-endian).

## Output schema

| Column           | Type    | Description                              |
|------------------|---------|------------------------------------------|
| packet_size_bytes| int     | UDP payload size                         |
| packet_rate_pps  | int     | Packet rate inferred from filename       |
| seq_no           | int     | Sequence number from payload             |
| sent_ts          | float   | TX timestamp (seconds, float)            |
| recv_ts          | float   | RX timestamp from PCAP header (seconds)  |
| owd_ms           | float   | One-way delay in milliseconds            |
| jitter_ms        | float   | |OWD_i − OWD_{i-1}| in milliseconds     |
| network_type     | string  | Always "SA" (5G Standalone)              |
| direction        | string  | Always "download"                        |
| capture_type     | string  | "E2E" or "core"                          |