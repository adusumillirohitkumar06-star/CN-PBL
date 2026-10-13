#!/usr/bin/env bash
# Capture DNS traffic to a pcap for use with Syntactica.
#
# DNS lives on UDP/53. This grabs DNS packets with tshark (Wireshark's CLI).
# Syntactica's reader accepts BOTH classic .pcap and pcapng (Wireshark's default),
# so either output works with: syntactica analyze <file>
#
# Usage:
#   scripts/capture.sh [interface] [count] [outfile]
# Examples:
#   scripts/capture.sh en0 500 mycapture.pcap
#   scripts/capture.sh                      # sensible defaults
#
# NOTE: capturing network traffic may require elevated privileges and, on shared
# networks, authorisation. Capture only traffic you are permitted to capture,
# and treat captures as sensitive.
set -euo pipefail

IFACE="${1:-any}"
COUNT="${2:-500}"
OUT="${3:-capture.pcap}"

if command -v tshark >/dev/null 2>&1; then
  echo "Capturing $COUNT DNS packets on '$IFACE' -> $OUT"
  tshark -i "$IFACE" -f "udp port 53" -c "$COUNT" -w "$OUT"
elif command -v tcpdump >/dev/null 2>&1; then
  echo "tshark not found; falling back to tcpdump"
  tcpdump -i "$IFACE" -c "$COUNT" -w "$OUT" "udp port 53"
else
  echo "Neither tshark nor tcpdump is installed. Install Wireshark and retry." >&2
  exit 1
fi

echo "Done. Load it with:"
echo "  python -c \"from syntactica.data import load_pcap; print(len(load_pcap('$OUT')), 'DNS messages')\""
