# Lab 06 — SIEM deployment and first detections

Continuation of [`lab-05-mgmt-bastion`](../lab-05-mgmt-bastion/). That lab ended with a demonstration that a session log stored on the host it audits can be destroyed by the user it records — and with the conclusion that the fix is to ship events off-host in real time.

This lab builds that. A dedicated SIEM segment (`intnet-siem`, `10.10.40.0/24`), Wazuh deployed on `siem-01`, agents on every host, and the first detection rules written against the environment's own telemetry.

It also tests the premise. Centralising events does resolve part of the Lab 05 limitation — what has been shipped is beyond the attacker's reach — but it does not protect what was never collected. That distinction is the through-line of this writeup.

## What it demonstrates

| Capability | Mechanism |
|---|---|
| Dedicated SIEM network | Sixth router leg `enp0s17` at `10.10.40.1`, `seg-siem` NM profile |
| Wazuh manager, indexer and dashboard | All-in-one install on `siem-01`, 4 GB |
| Telemetry from every host | Five agents reporting, including the manager's own |
| Dashboard reachable without exposing it | SSH port-forward through the bastion |
| Detection of scanning toward the management segment | Rules 100100 and 100101, mapped to T1046 |
| Detection of monitoring being disabled | Rule 100102, mapped to T1562.001 |
| Measured coverage, including what is not covered | [`coverage.md`](../coverage.md) |

## The SIEM segment

The sixth router leg was added from the host CLI, since the VirtualBox GUI still caps at four adapters:

    VBoxManage modifyvm "lab-router" --nic6 intnet --intnet6 "intnet-siem"

Placing the SIEM in its own segment rather than in SERVERS was deliberate: security data should not live where the systems it monitors live. An attacker who compromises `srv-web` should not find the record of that compromise on the same network.

Five firewall rules govern it, and their directions matter more than their ports:

    enp0s17 → enp0s3     53, 80, 443     SIEM reaches the internet, nothing more
    enp0s16 → enp0s17    22              bastion administers the SIEM
    enp0s16 → enp0s17    443             bastion reaches the dashboard
    {users,servers,dmz,mgmt} → enp0s17   1514, 1515   agents report

That last rule is the interesting one. It opens an **inbound** path into the segment holding the security data — the opposite of the management segment, where nothing may initiate a connection toward the bastion. A compromised host has a route to the collector.

The mitigation is that Wazuh authenticates agents with per-agent keys, so reaching the port is not enough. That mitigation is currently weaker than it should be: see the outstanding items.

## Dashboard access

The dashboard listens on 443, and the port was never exposed to the LAN. Access is an SSH port-forward through the bastion:

    ssh -L 8443:10.10.40.10:443 mgmt-01
    → https://localhost:8443

The traffic is encrypted by the tunnel, access is bound to an SSH credential, and no additional firewall rule was needed on the perimeter. It is the bastion pattern applied to a web service.

One detail worth recording from the install: Wazuh binds the indexer to loopback by default.

    0.0.0.0:1514              agents
    0.0.0.0:443               dashboard
    [::ffff:127.0.0.1]:9200   indexer — local only
    [::ffff:127.0.0.1]:9300   cluster — local only

Nothing off-box can query the index directly; the only path to the data is through the dashboard. That is the same `ListenAddress` reasoning applied to the router in Lab 03, here supplied by the installer rather than by configuration.

## First detection: the SIEM receives what it does not understand

The router's firewall drops were arriving, being decoded correctly, and generating nothing:

    **Phase 2: Completed decoding.
    action: 'FWD-DROP:'
    srcip: '10.10.10.10'      dstip: '10.10.99.10'
    srcport: '49168'          dstport: '22'

    **Phase 3: Completed filtering (rules).
    id: '4100'
    level: '0'
    description: 'Firewall rules grouped.'

Wazuh's `iptables-2` decoder handles the kernel's log format without modification, so every field was available. Rule 4100 is a container with **level 0**, which means no alert. Every dropped packet reached the manager, was parsed, and was discarded.

That is a sensible default — a firewall in a real network drops thousands of packets a day — but it means a newly installed SIEM sees nothing specific to the environment until someone teaches it to. The work was not writing a decoder. It was deciding what makes a dropped packet worth an alert.

## The rules

**100100 — level 8.** A blocked connection toward the management segment. Nothing should be trying to reach `10.10.99.0/24` from another segment; if something is, it is either misconfiguration or reconnaissance.

**100101 — level 10.** Six of those from one source inside sixty seconds. The threshold came from a measurement rather than a guess: a single `nc -z` produces **three** alerts from 100100, because TCP retransmits the SYN when nothing answers. A six-port scan would otherwise produce eighteen individual alerts and no summary.

**100102 — level 10.** Escalates Wazuh's rules 504, 505 and 506 — agent disconnected, removed, stopped — from level 3. Those three are distinct: an adversary using `kill -9` produces the first, one using `systemctl stop` produces the third. Covering one leaves a gap.

All three carry MITRE mappings. Wazuh resolves the tactic and technique name from the identifier alone, so the alerts arrive contextualised:

    Rule: 100102 (level 10) -> 'Wazuh agent stopped reporting - possible tampering with monitoring'
    mitre.id: ['T1562.001']
    mitre.tactic: ['Defense Evasion']
    mitre.technique: ['Disable or Modify Tools']

## Testing the Lab 05 premise

The reason for building this SIEM was that host-local logs cannot be trusted. So the first thing tested was whether centralising fixes it.

It does not — not for the logs that were never centralised. Truncating a session log on `mgmt-01` produced no alert of any kind, because `/var/log/session-logs/` was not among the agent's sources. The SIEM protects what it collects; it has nothing to say about what it does not.

Two approaches to closing that gap were tried and both failed, for different reasons. The full analysis is in [`coverage.md`](../coverage.md); the short version:

- **auditd** does not generate an event for the truncation as typed in an interactive shell, though it does for the same command run as `sh -c`. Confirmed by `strace` and by contrasting the two invocations in the raw audit log.
- **Wazuh FIM** detects it in principle and is unusable in practice: 287 alerts in twenty minutes, none of them the truncation, all of them sessions writing normally.

The compensating control is rule 100102. An adversary who disables monitoring is detected even though one who quietly truncates a file is not — watching for the absence of data rather than for the act of destroying it.

## Verification

| Test | Result |
|---|---|
| `agent_control -l` | Five agents `Active`, including the manager as local |
| `apt update` on `siem-01` | Succeeds — functional test of the 53/80/443 egress rule |
| `nc -z 10.10.40.10 443` from `mgmt-01` | `open` — dashboard reachable from the bastion only |
| `nc -z 10.10.99.10 22` from `ws-user01` | Blocked, rule 100100 fires |
| Six-port sweep from `ws-user01` | Rule 100101 fires, level 10 |
| `systemctl stop wazuh-agent` on `ws-user01` | Rule 100102 fires, level 10 |
| Truncating a session log on `mgmt-01` | **No alert** — documented limitation |
| Ruleset after a router reboot | Identical, all rules present |

Every rule above was verified by generating the event deliberately and observing the alert in `alerts.log`. A rule that passes `wazuh-logtest` but has never fired on live traffic is a different claim, and the distinction is kept throughout.

## Contents

    lab-06-siem/
    ├── README.md
    ├── logbook.md
    ├── configs/                        [pending collection]
    │   ├── local_rules.xml             The three detection rules
    │   ├── nftables-siem-rules.txt     Five firewall rules for the segment
    │   ├── agent-list.txt              agent_control -l output
    │   └── listening-sockets.txt       ss -lnt on siem-01 after install
    └── logs/                           [pending collection]
        ├── alert-100100.log            Blocked connection toward MGMT
        ├── alert-100101.log            Correlated scan
        ├── alert-100102.log            Agent stopped
        └── audit-invocation.log        The sh -c vs interactive contrast

Transfer route as usual: VM → `/media/sf_shared` → `mount_smbfs //agr86@192.168.0.41/vbox-shared ~/smbtest`, or `scp` through the bastion.

## Status and continuation

The environment has a SIEM. Five agents report, three detection rules fire on real activity, and coverage is measured rather than assumed — including the technique that is not covered.

What changed conceptually is smaller than it looks. The infrastructure was already segmented and hardened; what it lacked was the ability to say what had happened. It can now say that for a narrow and enumerated set of things, and the enumeration matters as much as the set.

**Lab 07:** the first full purple cycle against a deliberately vulnerable host. Exploit it, write the detection, measure whether the detection holds — and add the result to the coverage matrix whichever way it goes.
