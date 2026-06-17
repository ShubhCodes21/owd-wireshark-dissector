#!/usr/bin/env python3
"""
parse_pcaps_local.py
====================
Parses 5G campus PCAP files (from the IEEE DataPort dataset) and extracts
real one-way delay (OWD) values into a structured CSV.

USAGE
-----
1. Put this script in the SAME FOLDER as your .pcap files.
2. Open a terminal / command prompt in that folder.
3. Run:
     python parse_pcaps_local.py

That's it. No pip installs, no extra dependencies — uses only Python's
built-in struct module. Works on Windows, macOS, and Linux.

OUTPUT
------
Creates a file called  owd_dataset.csv  in the same folder, with columns:
   packet_size_bytes, packet_rate_pps, seq_no, sent_ts, recv_ts,
   owd_ms, jitter_ms, network_type, direction, capture_type

You can then upload that CSV (small) to Claude.

WHAT IT PROCESSES
-----------------
The script auto-detects which PCAP files are present and processes all of them.
File names should follow the dataset's pattern:
   <packet_size>.<packet_rate>.pcap         (E2E captures)
   <packet_size>.<packet_rate>.core.pcap    (Core captures)

For example:  128.100.pcap, 256.1000.pcap, 512.10000.core.pcap
"""

import os
import sys
import struct
import csv
import re
import time

# ─────────────────────────────────────────────────────────────────────────────
# PCAP PARSING CORE
# ─────────────────────────────────────────────────────────────────────────────

def read_pcap_global_header(f):
    """Read PCAP global header (24 bytes). Returns (endian, nano, network)."""
    hdr = f.read(24)
    if len(hdr) < 24:
        raise ValueError("File too short to be a valid PCAP")
    magic = struct.unpack('<I', hdr[0:4])[0]
    if magic == 0xa1b23c4d:
        endian, nano = '<', True
    elif magic == 0xa1b2c3d4:
        endian, nano = '<', False
    elif magic == 0x4d3cb2a1:
        endian, nano = '>', True
    elif magic == 0xd4c3b2a1:
        endian, nano = '>', False
    else:
        raise ValueError(f"Unknown PCAP magic: {hex(magic)}")
    network = struct.unpack(endian + 'I', hdr[20:24])[0]
    return endian, nano, network


def parse_owd_payload(pkt_data, offset):
    """Extract TS Seconds + TS Nano Seconds + Sequence Number from OWD payload.
    Returns (sent_ts, seq_no) or None if invalid."""
    if len(pkt_data) < offset + 20:
        return None
    try:
        ts_seconds = struct.unpack('>Q', pkt_data[offset:offset+8])[0]
        ts_nano    = struct.unpack('>Q', pkt_data[offset+8:offset+16])[0]
        seq_no     = struct.unpack('>I', pkt_data[offset+16:offset+20])[0]
    except struct.error:
        return None
    # Sanity-check Unix timestamp range (2020–2024 era)
    if ts_seconds < 1500000000 or ts_seconds > 1800000000:
        return None
    if ts_nano >= 2_000_000_000:
        return None
    sent_ts = ts_seconds + ts_nano * 1e-9
    return sent_ts, seq_no


def parse_e2e_pcap(filepath):
    """Parse an E2E PCAP, return list of {seq_no, sent_ts, recv_ts, owd_ms}."""
    results = []
    with open(filepath, 'rb') as f:
        endian, nano, network = read_pcap_global_header(f)
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + 'IIII', pkt_hdr)
            recv_ts = ts_sec + ts_usec * (1e-9 if nano else 1e-6)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            # Detect Ethernet vs raw IP
            if network == 1:
                if len(pkt_data) < 14:
                    continue
                eth_type = struct.unpack('>H', pkt_data[12:14])[0]
                if eth_type != 0x0800:
                    continue
                ip_offset = 14
            else:
                ip_offset = 0

            # IP header
            if len(pkt_data) < ip_offset + 20:
                continue
            ip_ihl = (pkt_data[ip_offset] & 0x0F) * 4
            ip_proto = pkt_data[ip_offset + 9]
            if ip_proto != 17:
                continue

            # UDP header
            udp_offset = ip_offset + ip_ihl
            if len(pkt_data) < udp_offset + 8:
                continue
            src_port = struct.unpack('>H', pkt_data[udp_offset:udp_offset+2])[0]
            dst_port = struct.unpack('>H', pkt_data[udp_offset+2:udp_offset+4])[0]

            # E2E: direct OWD packet on port 1337 -> 65001
            if src_port == 1337 and dst_port == 65001:
                owd_offset = udp_offset + 8
                parsed = parse_owd_payload(pkt_data, owd_offset)
                if not parsed:
                    continue
                sent_ts, seq_no = parsed
                owd_seconds = recv_ts - sent_ts
                results.append({
                    'seq_no': seq_no,
                    'sent_ts': sent_ts,
                    'recv_ts': recv_ts,
                    'owd_ms': owd_seconds * 1000,
                })
    return results


def parse_core_pcap(filepath):
    """Parse a core PCAP — extracts BOTH the direct OWD packets AND the
    GTP-wrapped versions. Computes core delay = |gtp_recv − direct_recv|
    matched by sequence number. Returns list of core delay records."""
    direct = {}   # seq_no -> recv_ts
    gtp    = {}   # seq_no -> recv_ts

    with open(filepath, 'rb') as f:
        endian, nano, network = read_pcap_global_header(f)
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + 'IIII', pkt_hdr)
            recv_ts = ts_sec + ts_usec * (1e-9 if nano else 1e-6)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            if network == 1:
                if len(pkt_data) < 14:
                    continue
                if struct.unpack('>H', pkt_data[12:14])[0] != 0x0800:
                    continue
                ip_offset = 14
            else:
                ip_offset = 0

            if len(pkt_data) < ip_offset + 20:
                continue
            ip_ihl = (pkt_data[ip_offset] & 0x0F) * 4
            if pkt_data[ip_offset + 9] != 17:
                continue

            udp_offset = ip_offset + ip_ihl
            if len(pkt_data) < udp_offset + 8:
                continue
            src_port = struct.unpack('>H', pkt_data[udp_offset:udp_offset+2])[0]
            dst_port = struct.unpack('>H', pkt_data[udp_offset+2:udp_offset+4])[0]

            if src_port == 1337 and dst_port == 65001:
                # Direct measurement packet (inside core)
                parsed = parse_owd_payload(pkt_data, udp_offset + 8)
                if parsed:
                    direct[parsed[1]] = recv_ts
            elif src_port == 2152 or dst_port == 2152:
                # GTP-U tunnel — unwrap to find inner measurement packet
                gtp_off = udp_offset + 8
                if len(pkt_data) < gtp_off + 8:
                    continue
                gtp_flags = pkt_data[gtp_off]
                inner_off = gtp_off + 8
                # Optional fields if any flag bit set
                if gtp_flags & 0x07:
                    if len(pkt_data) < inner_off + 4:
                        continue
                    next_ext = pkt_data[inner_off + 3]
                    inner_off += 4
                    while next_ext != 0x00:
                        if len(pkt_data) < inner_off + 1:
                            break
                        ext_len = pkt_data[inner_off] * 4
                        if ext_len == 0 or len(pkt_data) < inner_off + ext_len:
                            break
                        next_ext = pkt_data[inner_off + ext_len - 1]
                        inner_off += ext_len
                if len(pkt_data) < inner_off + 20:
                    continue
                inner_ihl = (pkt_data[inner_off] & 0x0F) * 4
                if pkt_data[inner_off + 9] != 17:
                    continue
                inner_udp_off = inner_off + inner_ihl
                if len(pkt_data) < inner_udp_off + 8:
                    continue
                isp = struct.unpack('>H', pkt_data[inner_udp_off:inner_udp_off+2])[0]
                idp = struct.unpack('>H', pkt_data[inner_udp_off+2:inner_udp_off+4])[0]
                if isp == 1337 and idp == 65001:
                    parsed = parse_owd_payload(pkt_data, inner_udp_off + 8)
                    if parsed:
                        gtp[parsed[1]] = recv_ts

    matched_seqs = set(direct.keys()) & set(gtp.keys())
    core_records = []
    for seq_no in sorted(matched_seqs):
        core_records.append({
            'seq_no': seq_no,
            'direct_ts': direct[seq_no],
            'gtp_ts': gtp[seq_no],
            'core_delay_us': abs(gtp[seq_no] - direct[seq_no]) * 1e6,
        })
    return core_records


# ─────────────────────────────────────────────────────────────────────────────
# FILE DISCOVERY + ORCHESTRATION
# ─────────────────────────────────────────────────────────────────────────────

# Pattern: <size>.<rate>.pcap  or  <size>.<rate>.core.pcap
FILE_PATTERN = re.compile(
    r'^(\d+)\.(\d+)(?:\.(core))?\.pcap$',
    re.IGNORECASE
)


def discover_pcaps(folder):
    """Find all matching PCAP files in folder. Returns list of dicts."""
    found = []
    for name in os.listdir(folder):
        m = FILE_PATTERN.match(name)
        if not m:
            continue
        size = int(m.group(1))
        rate = int(m.group(2))
        is_core = m.group(3) is not None
        found.append({
            'path': os.path.join(folder, name),
            'name': name,
            'packet_size': size,
            'packet_rate': rate,
            'is_core': is_core,
        })
    return found


def human_size(n_bytes):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} TB"


def main():
    folder = os.path.dirname(os.path.abspath(__file__))
    print("=" * 70)
    print("5G CAMPUS NETWORK PCAP PARSER")
    print("=" * 70)
    print(f"Looking for PCAP files in: {folder}")
    print()

    pcaps = discover_pcaps(folder)
    if not pcaps:
        print("ERROR: No PCAP files found matching the pattern <size>.<rate>.pcap")
        print("Make sure this script is in the same folder as your .pcap files.")
        sys.exit(1)

    e2e_files  = sorted([p for p in pcaps if not p['is_core']],
                        key=lambda p: (p['packet_size'], p['packet_rate']))
    core_files = sorted([p for p in pcaps if p['is_core']],
                        key=lambda p: (p['packet_size'], p['packet_rate']))

    print(f"Found {len(e2e_files)} E2E files and {len(core_files)} core files:")
    print()
    print(f"  {'File':<35} {'Size':>10}    {'Type':<5}")
    print(f"  {'-'*35} {'-'*10}    {'-'*5}")
    for p in pcaps:
        size_bytes = os.path.getsize(p['path'])
        kind = 'core' if p['is_core'] else 'E2E'
        print(f"  {p['name']:<35} {human_size(size_bytes):>10}    {kind}")
    print()

    # ─── Process E2E PCAPs ───
    out_csv = os.path.join(folder, 'owd_dataset.csv')
    print(f"Output will be written to: {out_csv}")
    print()
    print("=" * 70)
    print("PROCESSING E2E PCAP FILES (extracting one-way delay per packet)")
    print("=" * 70)

    total_rows = 0
    with open(out_csv, 'w', newline='') as cf:
        writer = csv.writer(cf)
        writer.writerow([
            'packet_size_bytes', 'packet_rate_pps', 'seq_no',
            'sent_ts', 'recv_ts', 'owd_ms', 'jitter_ms',
            'network_type', 'direction', 'capture_type'
        ])

        for fmeta in e2e_files:
            print(f"\n>>> {fmeta['name']}  (size={fmeta['packet_size']}B, rate={fmeta['packet_rate']}pps)")
            t0 = time.time()
            try:
                records = parse_e2e_pcap(fmeta['path'])
            except Exception as e:
                print(f"  ERROR: {e}")
                continue
            elapsed = time.time() - t0
            print(f"  Extracted {len(records)} OWD measurements in {elapsed:.1f}s")

            if records:
                owds = [r['owd_ms'] for r in records]
                valid = [o for o in owds if 0 < o < 1000]
                if valid:
                    mean_o = sum(valid) / len(valid)
                    print(f"  Mean OWD: {mean_o:.3f} ms, range: {min(valid):.3f} – {max(valid):.3f} ms")

                # Write rows
                for i, r in enumerate(records):
                    if not (0 < r['owd_ms'] < 1000):
                        continue
                    jitter = abs(r['owd_ms'] - records[i-1]['owd_ms']) if i > 0 else 0.0
                    writer.writerow([
                        fmeta['packet_size'], fmeta['packet_rate'], r['seq_no'],
                        f"{r['sent_ts']:.9f}", f"{r['recv_ts']:.9f}",
                        f"{r['owd_ms']:.6f}", f"{jitter:.6f}",
                        'SA', 'download', 'E2E'
                    ])
                    total_rows += 1

    print()
    print("=" * 70)
    print(f"DONE. Wrote {total_rows} rows to {out_csv}")
    print("=" * 70)
    print()

    # ─── Process core PCAPs (optional, smaller summary file) ───
    if core_files:
        print("PROCESSING CORE PCAP FILES (computing core processing delay)")
        print("-" * 70)
        core_csv = os.path.join(folder, 'core_delay_summary.csv')
        with open(core_csv, 'w', newline='') as cf:
            writer = csv.writer(cf)
            writer.writerow([
                'packet_size_bytes', 'packet_rate_pps',
                'matched_pairs', 'mean_core_delay_us',
                'min_core_delay_us', 'max_core_delay_us', 'std_core_delay_us',
            ])
            for fmeta in core_files:
                print(f"\n>>> {fmeta['name']}")
                try:
                    records = parse_core_pcap(fmeta['path'])
                except Exception as e:
                    print(f"  ERROR: {e}")
                    continue
                if not records:
                    print("  No matched seq pairs found.")
                    continue
                cds = [r['core_delay_us'] for r in records if 0 < r['core_delay_us'] < 100000]
                if not cds:
                    continue
                mean_cd = sum(cds) / len(cds)
                var = sum((x - mean_cd) ** 2 for x in cds) / len(cds)
                std_cd = var ** 0.5
                print(f"  Matched {len(cds)} pairs.  Mean core delay: {mean_cd:.1f} us")
                writer.writerow([
                    fmeta['packet_size'], fmeta['packet_rate'],
                    len(cds), f"{mean_cd:.2f}", f"{min(cds):.2f}",
                    f"{max(cds):.2f}", f"{std_cd:.2f}",
                ])
        print()
        print(f"Core delay summary written to: {core_csv}")
        print()

    # ─── Final instructions ───
    print("=" * 70)
    print("NEXT STEP")
    print("=" * 70)
    print("Upload the file(s) below to Claude:")
    print(f"  - owd_dataset.csv         (main dataset, {total_rows:,} rows)")
    if core_files and os.path.exists(os.path.join(folder, 'core_delay_summary.csv')):
        print(f"  - core_delay_summary.csv  (core processing delay summary)")
    print()
    print("If owd_dataset.csv is too large to upload (>30 MB), you can split it")
    print("by packet rate before uploading — let Claude know and it will tell you")
    print("how. Alternatively, only upload the rates you have not processed yet.")
    print()


if __name__ == '__main__':
    main()
