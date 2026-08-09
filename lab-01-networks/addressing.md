# Addressing plan — Lab 01

**Environment:** VirtualBox on Windows 11 · Debian 13 (Trixie) · NetworkManager
**State:** Session 1 — segments operational, inter-segment forwarding disabled
**Date:** 2026-08-08 (lab) · 2026-08-09 (evidence collection)

---

## 1. Segments

| Segment | Network | Gateway | Interface on `lab-router` | VirtualBox internal network | State |
|---|---|---|---|---|---|
| NAT uplink | `10.0.2.0/24` | `10.0.2.2` | `enp0s3` (DHCP) | NAT | Operational |
| USERS | `10.10.10.0/24` | `10.10.10.1` | `enp0s8` | `intnet-users` | Operational |
| SERVERS | `10.10.20.0/24` | `10.10.20.1` | `enp0s9` | `intnet-servers` | Operational, no hosts |
| DMZ | `10.10.30.0/24` | `10.10.30.1` | `enp0s10` | `intnet-dmz` | Operational, no hosts |

Lab DNS resolver: `10.0.2.3` (VirtualBox internal resolver). It does not resolve yet because forwarding is disabled; it is configured in advance for Session 2.

## 2. Address assignment

| Host | Segment | Address | Gateway | NM profile | Role |
|---|---|---|---|---|---|
| `lab-router` | All | `.1` in each segment | `10.0.2.2` (via NAT) | `seg-users`, `seg-servers`, `seg-dmz` | Multi-homed router |
| `ws-user01` | USERS | `10.10.10.10/24` | `10.10.10.1` | `ws-lan` | Workstation |
| `debian-base` | — | — | — | — | Template, powered off |

### Numbering convention

| Range | Reserved for |
|---|---|
| `.1` | Gateway (router interface) |
| `.2 – .9` | Network infrastructure (future: DHCP, DNS) |
| `.10 – .99` | Static hosts |
| `.100 – .199` | DHCP pool (future) |
| `.200 – .254` | Temporary testing |

Reserving ranges up front avoids the painful renumbering later. It is the same criterion applied in production, except that here it costs five minutes and there it costs a maintenance window.

## 3. Design rationale

### Why three segments instead of a flat network

A flat network means a single broadcast domain: every host sees every other host's ARP traffic and can reach any of them without passing through any control point. During an intrusion, that turns a compromised user laptop into direct access to the servers. Segmentation does not prevent the intrusion; it **constrains the lateral movement that follows**, which is the factor deciding whether an incident is one reimaged machine or a week of response work.

The three segments reproduce the standard separation by exposure level:

- **USERS** — end-user machines. High probability of initial compromise (phishing, browsing, USB), low intrinsic value.
- **SERVERS** — internal services. Low exposure, high value. Must never be directly reachable from USERS without an explicit policy allowing it.
- **DMZ** — services published externally. Maximum exposure by design, therefore assumed compromisable and isolated from the other two.

### Why a `/24` per segment

254 usable addresses is generously excessive for a lab, but a readable third octet (`10.10.**10**.x` = USERS, `10.10.**20**.x` = SERVERS, `10.10.**30**.x` = DMZ) makes zone membership readable at a glance in any log, packet capture or firewall rule. When you are reading `tcpdump` output at two in the morning, that readability is worth more than address-space efficiency.

### Why the router carries no gateway on its internal interfaces

Only one default route can exist per routing table. The router learns its own via DHCP on `enp0s3` (`default via 10.0.2.2`). Its three internal legs are **directly connected** networks: the kernel generates the corresponding route automatically when the address is assigned, and it does not need to be told where to hand that traffic.

Setting a gateway on multiple interfaces is the classic mistake in this configuration. NetworkManager accepts the instruction, and the result is a routing table with competing default routes and intermittent connectivity depending on which one wins on metric.

`ws-user01` **does** carry a gateway, because it has only one path out: anything not in `10.10.10.0/24` goes to `10.10.10.1`. That asymmetry — router without an internal gateway, client with one — is the essence of routing.

### Why IPv6 is disabled

`ipv6.method disabled` on every profile. In a segmentation lab, active IPv6 introduces a parallel addressing plane (link-local, SLAAC autoconfiguration) that can establish connectivity along paths the design never accounted for. That is exactly the kind of undocumented route that invalidates an isolation test. It will be reintroduced deliberately when it is the subject of study.

## 4. Current forwarding state

```
net.ipv4.ip_forward = 0
```

The router responds from **all** of its addresses — it has a leg in every network — but forwards nothing between interfaces. Behaviour verified from `ws-user01`:

| Destination | Result | Reason |
|---|---|---|
| `10.10.10.1` | Replies | Router's local interface in the same segment |
| `10.10.20.1` | Replies | Another interface on the same router; replies even though the packet arrives on `enp0s8` |
| `8.8.8.8` | Silent drop | The kernel receives a packet not addressed to itself, checks `ip_forward = 0`, and drops it without generating ICMP |

The diagnostic nuance: the failure toward `8.8.8.8` is **silent**. There is no `Destination Host Unreachable`, because that message is generated by the source machine itself when it cannot resolve ARP on its own segment. Here ARP does resolve, the packet reaches the router, and it dies there without notice. Distinguishing "fails loudly on my own machine" from "fails silently further along" is the first step in any connectivity diagnosis.

## 5. Planned for Session 2

- Enable `net.ipv4.ip_forward = 1` persistently (`/etc/sysctl.d/`)
- Outbound NAT with `nftables` (masquerade on `enp0s3`)
- Verify the TTL drop to 63 as evidence of a routing hop
- First inter-segment filtering rules: deny USERS → SERVERS by default
