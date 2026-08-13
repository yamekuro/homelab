# Lab 02 — NAT and inter-segment filtering

Continuation of [`lab-01-networks`](../lab-01-networks/). The three segments built there were isolated because the router forwarded nothing at all. This lab enables forwarding — which is what internal hosts need to reach the internet — and then restores isolation deliberately, through policy rather than through incapacity.

That distinction is the whole point. A network that is isolated because nothing works is not defended; it is broken. A network that forwards what it should and refuses what it should not, and records every refusal, is defended and observable.

## What it demonstrates

| Capability | Mechanism |
|---|---|
| Internal hosts reach the internet | `ip_forward` plus `masquerade` on the external leg |
| Segments cannot reach each other | `forward` chain with `policy drop` |
| Every denied attempt is recorded | `log prefix "FWD-DROP: "` before the drop |
| Configuration survives reboot | `/etc/sysctl.d/` and `/etc/nftables.conf` |

## The problem forwarding alone does not solve

Enabling `net.ipv4.ip_forward = 1` made the router relay packets, and connectivity still failed. A capture on the external interface showed why:

    10.10.10.10 > 8.8.8.8: ICMP echo request, seq 1
    10.10.10.10 > 8.8.8.8: ICMP echo request, seq 2
    10.10.10.10 > 8.8.8.8: ICMP echo request, seq 3

Three requests leaving, no replies. Forwarding worked; the packets carried a source address from `10.10.10.0/24`, a private range that exists only inside this lab. The destination had nowhere to send a reply.

After adding masquerade, the same test on the same host:

    10.0.2.15 > 8.8.8.8: ICMP echo request, seq 1
    8.8.8.8 > 10.0.2.15: ICMP echo reply, seq 1

The router rewrites the source to its own external address on the way out, and uses connection tracking to return each reply to the internal host that originated it. Both captures are in [`captures/`](captures/).

## Configuration

**Forwarding**, persistent in `/etc/sysctl.d/99-lab-router.conf`:

    net.ipv4.ip_forward = 1

**Ruleset**, persistent in `/etc/nftables.conf`:

    table ip lab-nat {
        chain postrouting {
            type nat hook postrouting priority srcnat; policy accept;
            oifname "enp0s3" ip saddr 10.10.0.0/16 counter masquerade
        }
    }
    table ip lab-filter {
        chain forward {
            type filter hook forward priority filter; policy drop;
            ct state established,related counter accept
            iifname { "enp0s8", "enp0s9", "enp0s10" } oifname "enp0s3" counter accept
            counter log prefix "FWD-DROP: " drop
        }
    }

Rule order matters. `established,related` comes first because it matches the overwhelming majority of packets — once a conversation is registered in the connection tracking table, everything that follows belongs to it. The counters confirm this: a three-packet ping produced 1 hit on the outbound rule and 3 on `established`.

## Verification

From `ws-user01` (`10.10.10.10`), after a clean reboot with no manual intervention:

| Test | Result | Meaning |
|---|---|---|
| `ping 8.8.8.8` | Replies, `ttl=62` | Forwarded, masqueraded, returned |
| `ping 10.10.20.50` | Silent failure | Dropped by policy, logged |
| `ping 10.10.20.1` | Replies, `ttl=64` | Router's own interface — never traverses `forward` |

### Why TTL 62 and not 63

Session 1 documented `ttl=64` as the baseline for a local reply and predicted 63 after one routing hop. The observed value is 62, because the path crosses two routers: `lab-router`, and then VirtualBox's own NAT gateway at `10.0.2.2`.

The topology diagram shows one router. The packet crosses two. That gap between documented and actual infrastructure is exactly what a `traceroute` exposes in a production network, and the reason TTL is worth reading rather than ignoring.

### What a denied attempt looks like

    FWD-DROP: IN=enp0s8 OUT=enp0s9 SRC=10.10.10.10 DST=10.10.20.50
    LEN=84 TTL=63 PROTO=ICMP TYPE=8 ID=6 SEQ=1

`IN` and `OUT` being different interfaces confirms this is forwarded traffic. `TTL=63` shows the packet was already decremented before the drop decision. `TYPE=8` is an echo request. Full log in [`logs/fwd-drop.log`](logs/fwd-drop.log).

One such entry is noise. A hundred of them from one source, walking `10.10.20.1` through `10.10.20.254` in thirty seconds, is a host in USERS scanning the server segment — lateral movement in its reconnaissance phase. This lab produces the telemetry that would make that visible.

## The input chain is not filtered

`ping 10.10.20.1` from USERS still succeeds, and this is correct rather than a gap in the rules.

That address belongs to the router. Traffic addressed to the machine itself traverses the `input` chain; traffic passing through it traverses `forward`. Only `forward` carries a policy here, so the router still answers on all four of its addresses from any segment.

Related: `ss -tlnp` shows sshd bound to `0.0.0.0:22` — reachable from every segment including the external leg. Both are deferred to Lab 03.

## Contents

    lab-02-nat-firewall/
    ├── README.md              This document
    ├── logbook.md             Session record: failures, diagnosis, concepts
    ├── captures/
    │   ├── nat-before.pcap    Forwarding on, NAT off — requests leave, nothing returns
    │   ├── nat-before.txt
    │   ├── nat-after.pcap     Same test with masquerade — full request/reply pairs
    │   └── nat-after.txt
    ├── configs/
    │   ├── nftables-ruleset.txt
    │   └── routing-table.txt
    └── logs/
        └── fwd-drop.log       Denied inter-segment attempts

## Status and continuation

Complete and verified after reboot. Snapshot `sesion02-completa` taken on both VMs with them powered off.

**Lab 03:** filter the `input` chain, restrict sshd to internal interfaces via `ListenAddress`, and deploy a host in SERVERS — currently the segment is empty, which means inter-segment isolation can only be verified against a non-existent destination rather than a live one.
