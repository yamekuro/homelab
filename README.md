# homelab

Personal lab for systems administration and security engineering. Each directory is a self-contained exercise: what was built, why it was designed that way, the configuration as it actually ran, captured evidence, and a logbook of what failed and what that failure taught.

The lab runs on VirtualBox over a Windows 11 host, with Debian 13 (Trixie) guests and a macOS laptop as the administration workstation.

## Method

Every exercise follows one loop: **build, attack what you built, detect it, document the limits.** Offensive technique is not the goal — it exists to drive and validate defence. A control is not trusted until it has been attacked, and the attack that succeeds is worth more than the configuration that appeared to work.

This is purple-team methodology in service of a defensive objective. The target role is SOC analyst; the route there runs through understanding attacks well enough to detect them, and proving the detection works rather than assuming it.

The phased plan is in [`curriculum.md`](curriculum.md).

---

## Labs

### [`lab-01-networks`](lab-01-networks/) — Network segmentation

Multi-homed router with one interface in each of three isolated segments (USERS, SERVERS, DMZ) plus a NAT uplink, and a client deployed in USERS.

The exercise deliberately stops before enabling `ip_forward`, because the intermediate state — a router that replies from every address yet routes nothing between them — is what makes visible what forwarding actually contributes. Verified with ping behaviour across all three segments and a `tcpdump` ARP capture establishing a layer 2 baseline.

Covers: NetworkManager profiles via `nmcli`, connected vs. learned vs. static routes, ARP resolution and revalidation patterns, SSH key-based transfer between hosts, and layered connectivity diagnosis.

### [`lab-02-nat-firewall`](lab-02-nat-firewall/) — NAT and inter-segment filtering

Forwarding enabled, NAT with masquerade for internet access, and a `forward` chain with a default-deny policy and explicit logging on every refusal.

Filtering traffic *through* the router while leaving traffic addressed *to* it unrestricted is the gap this lab opens and the next one closes — a deliberate sequence, because the two chains are separate paths and conflating them is a common error.

Covers: `nftables` tables and chains, masquerade, default-deny policy, drop logging, and TTL as evidence of the path a packet took.

### [`lab-03-hardening`](lab-03-hardening/) — Router hardening

Default-deny on the `input` chain, sshd bound only to internal interfaces, persistent logging, and the removal of everything the machine does not need in order to be a router.

Enabling logging on the drop rule turned the firewall from a barrier into a sensor, and produced the session's most useful finding: 104 of 110 dropped packets were the router announcing itself by multicast across three segments, from a printer-discovery service that had no business running. The correct response was to remove the cause, not to add a rule silencing it.

Covers: `input` vs `forward` as separate paths, `ListenAddress` as defence in depth, boot-order dependencies in systemd, reading logs at volume, and `drop` versus `reject` as different signals to a scanner.

### [`lab-04-srv-web`](lab-04-srv-web/) — Live service and isolation under test

A minimal Debian host running nginx deployed in SERVERS, so that inter-segment isolation could finally be tested against a destination that answers.

The same address returns `200 OK` locally and times out from USERS, with the refusal logged on the router. For three labs the policy had only been tested against addresses where nothing existed, where a drop and an absence are indistinguishable from the client. Administration was established through a bastion jump — the correct pattern, implemented as a laboratory shortcut, and recorded as such.

Covers: `output` as a third path distinct from `input` and `forward`, privilege separation in daemon design, response headers as reconnaissance, and why a blocked attack leaves its trace on a different host than a successful one.

### [`lab-05-mgmt-bastion`](lab-05-mgmt-bastion/) — Management segment and bastion

A dedicated management network and purpose-built jump host, replacing the shortcut Lab 04 left behind. The router is then removed as a bastion in three independent layers — credential, service, firewall — and administers nothing.

The most useful material came from attacking what had just been built. The session-recording mechanism installed here was defeated three ways: the log truncates without privilege, it then refills with nulls and regains a plausible size so the tampering is invisible to a size check, and reading it executes the control sequences it recorded — including through `scriptreplay`, the tool built for the purpose. Host-local audit cannot be made tamper-resistant, which is the argument for shipping events off-host.

Covers: ProxyJump and why a jump host never sees the credential, one-directional forward rules, rule placement in an ordered ruleset, positive controls, and terminal escape injection.

---

## Reference

**[`curriculum.md`](curriculum.md)** — the phased plan: thirty modules from networking fundamentals through detection engineering, cloud, OT/ICS and AI security, with scope decisions recorded for each.

**[`command-reference.md`](command-reference.md)** — running reference of every command used across the lab, grouped by purpose rather than by session, with the reasoning behind each one.

---

## How each lab is documented

| File | Contents |
|---|---|
| `README.md` | What was built and what it demonstrates |
| `logbook.md` | Session record: failures with diagnosis, concepts consolidated, and what remains open |
| `configs/` | Configuration exported from each machine as it actually ran |
| `logs/` · `captures/` | Log and traffic evidence, where the exercise produced any |
| `topology.svg` · `addressing.md` | Diagram and addressing plan, for the labs that changed the topology |

The logbook is the part worth reading. Failures are numbered in one continuous sequence across the whole repository rather than restarting each lab, because the useful ones recur: a name that does not match exactly, a check that reports success without having verified anything, a command run on the wrong machine. It documents what went wrong, why the symptom was misleading, and what measure was adopted — including the diagnoses that turned out to be mine rather than the system's.

A lab that worked first time demonstrates that instructions were followed; a documented failure demonstrates method.

---

## Structure

Each phase builds on infrastructure the previous one left running, so the lab accumulates rather than resetting between exercises. Open items are tracked in the logbook of the lab that raised them and closed in the one that resolves them, which is why the writeups reference each other in both directions.

Exercises are added as they are completed. Nothing here is aspirational.

---

## Background

Ten years as a graphic designer in broadcast and print, now working toward systems and security engineering. The design background is not incidental to this repository: infrastructure diagrams, incident write-ups, and technical documentation are things engineering teams need and rarely have someone who can do well.
