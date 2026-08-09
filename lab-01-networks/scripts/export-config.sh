#!/usr/bin/env bash
# Exports the current VM's network state to a dated file.
# Usage:  ./export-config.sh   (run INSIDE each VM)
# Then copy the result to lab-01-networks/configs/ on the host.

set -euo pipefail

HOST=$(hostname)
OUT="${HOME}/${HOST}-network-$(date +%Y%m%d).txt"

{
  echo "# Network configuration — ${HOST}"
  echo "# Generated: $(date -Is)"
  echo "# System:    $(. /etc/os-release && echo "$PRETTY_NAME") · kernel $(uname -r)"
  echo

  echo "## Interfaces (link layer)"
  ip -br link
  echo

  echo "## Addresses"
  ip -br addr
  echo

  echo "## Routing table"
  ip route
  echo

  echo "## IPv4 forwarding"
  sysctl net.ipv4.ip_forward
  echo

  echo "## NetworkManager profiles"
  nmcli -t -f NAME,DEVICE,TYPE,STATE connection show
  echo

  echo "## Profile detail (ipv4/ipv6/connection fields only)"
  while IFS= read -r profile; do
    [ -z "$profile" ] && continue
    echo
    echo "### ${profile}"
    nmcli connection show "$profile" \
      | grep -E '^(connection\.(id|interface-name|autoconnect)|ipv4\.(method|addresses|gateway|dns)|ipv6\.method)' \
      || true
  done < <(nmcli -t -f NAME connection show)
  echo

  echo "## ARP neighbour table"
  ip neigh
} > "$OUT"

echo "Written: $OUT"
echo
echo "Copy it to the host with:"
echo "  scp ${USER}@$(hostname -I | awk '{print $1}'):${OUT} ./configs/"
