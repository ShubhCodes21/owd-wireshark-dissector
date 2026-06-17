# Sample Output

No PCAP files are included in this repository. The TU Dresden dataset
is hosted on IEEE DataPort and requires a free account to download.

## Where to Get the PCAPs

1. Create a free account at: https://ieee-dataport.org
2. Navigate to the dataset:
   https://ieee-dataport.org/open-access/5g-campus-networks-measurement-dataset
3. Download the PCAP archive (~several GB)

## File Naming Convention

The dataset uses this naming pattern:
{packet_size}.{packet_rate}.pcap         End-to-end captures

{packet_size}.{packet_rate}.core.pcap    Core network captures

Examples:
- `128.100.pcap`       128-byte packets at 100 pps, end-to-end
- `512.1000.core.pcap` 512-byte packets at 1000 pps, core capture

## What the Parser Produces

Running `parse_pcaps.py` on a folder of PCAPs produces a CSV like this:
packet_size_bytes,packet_rate_pps,seq_no,sent_ts,recv_ts,owd_ms,jitter_ms,...

128,100,0,1620958711.998036,1620958712.002470,4.433870,0.000000,...

128,100,1,1620958712.008022,1620958712.012489,4.467000,0.033130,...

A 300,000-row CSV extracted from the 100 pps captures across 3 packet
sizes (128, 256, 512 bytes) is approximately 24 MB.