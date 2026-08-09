# homelab

Personal lab for systems administration and security engineering. Each directory is a self-contained exercise: what was built, why it was designed that way, the configuration as it actually ran, captured evidence, and a logbook of what failed and what that failure taught.

The lab runs on VirtualBox over a Windows 11 host, with Debian 13 (Trixie) guests and a macOS laptop as the administration workstation.

---

## Labs

### [`lab-01-networks`](lab-01-networks/) — Network segmentation

Multi-homed router with one interface in each of three isolated segments (USERS, SERVERS, DMZ) plus a NAT uplink, and a client deployed in USERS.

The exercise deliberately stops before enabling `ip_forward`, because the intermediate state — a router that replies from every address yet routes nothing between them — is what makes visible what forwarding actually contributes. Verified with ping behaviour across all three segments and a `tcpdump` ARP capture establishing a layer 2 baseline.

Covers: NetworkManager profiles via `nmcli`, connected vs. learned vs. static routes, ARP resolution and revalidation patterns, SSH key-based transfer between hosts, and layered connectivity diagnosis.

---

## Reference

**[`command-reference.md`](command-reference.md)** — running reference of every command used across the lab, grouped by purpose rather than by session, with the reasoning behind each one.

---

## How each lab is documented

| File | Contents |
|---|---|
| `README.md` | What was built and what it demonstrates |
| `topology.svg` / `.png` | Network diagram, editable vector source retained |
| `addressing.md` | Addressing plan and the rationale for each design decision |
| `logbook.md` | Session record: failures with diagnosis, and concepts consolidated |
| `configs/` | Configuration exported from each machine as it actually ran |
| `captures/` | Traffic evidence |
| `scripts/` | Tooling written for the exercise |

The logbook is the part worth reading. It documents what went wrong, why the symptom was misleading, and what measure was adopted — including the diagnoses that turned out to be mine rather than the system's. A lab that worked first time demonstrates that instructions were followed; a documented failure demonstrates method.

---

## Structure

The work follows a phased curriculum moving from networking fundamentals through system hardening, monitoring, and detection engineering. Each phase builds on infrastructure the previous one left running, so the lab accumulates rather than resetting between exercises.

Exercises are added as they are completed. Nothing here is aspirational.

---

## Background

Ten years as a graphic designer in broadcast and print, now working toward systems and security engineering. The design background is not incidental to this repository: infrastructure diagrams, incident write-ups, and technical documentation are things engineering teams need and rarely have someone who can do well.
