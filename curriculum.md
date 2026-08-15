# Curriculum

The phased curriculum for this homelab. Thirty modules moving from networking
fundamentals through hardening, monitoring, detection engineering, and into
specialised domains (cloud, OT/ICS, AI security).

## Method: purple by construction

Every module follows one loop: **build, attack what you built, detect it,
document the limits.** Offensive technique is not the goal — it exists to drive
and validate detection. Each attack executed is paired with the detection written
to catch it, and each detection is measured for coverage.

This is purple-team methodology: red and blue working the same problem, where
every technique feeds directly into defensive capability. The objective remains
defensive — the target role is SOC N2 analyst — but the route there runs through
understanding attacks well enough to detect them, and proving that the detection
works rather than assuming it.

The organising principle is continuity: each module builds on infrastructure the
previous one left running, so the lab accumulates rather than resetting.

> **Status note.** This is a working plan, not a schedule. Modules are completed
> in order but timing is deliberately unstated: depth is the goal, not pace.
> Scope decisions (which modules go to full depth, which stop at conceptual
> familiarity, and why) are recorded separately in `roadmap.md`.
>
> **Maintenance note.** Fast-moving modules (AI security, cloud, commercial
> tooling) carry a "valid as of" date. The curriculum is reviewed at the start of
> each phase — checking what has changed in that phase's tooling — rather than on
> a fixed clock. Reviewing tooling months before it's used wastes effort; tying
> review to phase entry keeps it current when it matters.

---

## Numbering: labs vs modules

A **module** is a curriculum unit. A **lab** is a single hands-on exercise with
its own writeup. One module contains several labs. The two numberings are
independent — Module 1 alone contains Labs 01–05.

| | |
|---|---|
| Module | Curriculum unit (M1–M30) |
| Lab | Individual exercise (`lab-NN-descriptive-name`) |

---

## The purple loop, made explicit

From the first detection module onward, every technique studied is run through
four steps, and the writeup documents all four:

1. **Build** — stand up the target or capability.
2. **Attack** — execute the technique. Where a catalogued execution exists
   (Atomic Red Team), use it, so the attack maps cleanly to an ATT&CK technique
   rather than being ad hoc.
3. **Detect** — write and tune the rule that catches it.
4. **Measure** — record detection coverage: which techniques are seen, which are
   not, and time-to-detection. The coverage matrix is itself a deliverable.

A gap found in step 4 is not a failure — it is the most valuable output. A
documented blind spot demonstrates that the detection was actually tested.

---

## Phase 1 — Network foundations

Segmented infrastructure that later phases generate telemetry on. This is
infrastructure, not a SOC: no SIEM, no agents, no rules yet.

**M1 — Network segmentation and routing** *(in progress)*
Multi-homed Debian router; four internal segments (USERS, SERVERS, DMZ, MGMT)
plus NAT uplink; inter-segment filtering; router hardening; management segment
and bastion architecture.
Labs 01–05 complete. Covers: routing, nftables, NAT/DNAT, default-deny policy,
surface reduction, SSH key architecture, ProxyJump, session recording.

**M2 — Traffic analysis fundamentals**
Wireshark and `tcpdump` in depth on the traffic the segmented lab already
produces. Reading a capture, following streams, spotting anomalies. The
transferable skill underneath every later detection module.

---

## Phase 2 — Endpoints and telemetry

Turning silent infrastructure into a source of logs.

**M3 — Endpoint hardening (Linux)**
CIS-style baseline on the Debian hosts: auditd, PAM, filesystem controls,
service minimisation. Measured, not asserted.

**M4 — Endpoint hardening (Windows)**
A Windows VM added to USERS. Group Policy baseline, Windows security logging,
Sysmon deployment and configuration.

**M5 — Log centralisation**
Deploying the SIEM (Wazuh) and getting agents on every host. Log forwarding,
parsing, and the first taste of why local logs don't survive a privileged user
— the limitation demonstrated back in Lab 05.

---

## Phase 3 — Detection engineering (purple loop begins)

The core of the project. From here, every module is a full purple cycle:
build, attack (Atomic Red Team where applicable), detect, measure coverage.

**M6 — First victim machine + paired detection**
A deliberately vulnerable host in DMZ. Exploit it, then write the Wazuh rule
that catches the activity. Establishes the build-attack-detect-measure loop as
the repeating pattern, and introduces the detection-coverage matrix.
*(This is Lab 06 — the immediate next exercise.)*

**M7 — Enumeration and its detection**
Port scans, service enumeration, brute force — executed via Atomic Red Team so
each maps to an ATT&CK technique. What each leaves in the logs, the rules that
surface it, false-positive reduction, and coverage recorded.

**M8 — Web exploitation and its detection**
Common web attacks against a vulnerable app; detection from application and
proxy logs; coverage matrix updated.

**M9 — Privilege escalation and its detection**
Linux and Windows privesc paths. `linpeas`/`winpeas`. What escalation looks like
in Sysmon and auditd. Atomic executions where available.

**M10 — MITRE ATT&CK mapping and coverage**
Formalising the method: the detection-coverage matrix becomes the central
artifact. Every rule mapped to a technique, every gap made visible.
Threat-informed defence as explicit practice, with Atomic Red Team as the
verification tool.

**M11 — Detection tuning and false positives**
The unglamorous, high-value skill. Baselining, allowlisting, alert fatigue, and
the heartbeat problem — distinguishing "no attack" from "the parser broke."

---

## Phase 4 — Active Directory (purple loop)

The environment most enterprises actually run, and the one N2 analysts spend
their time defending.

**M12 — AD deployment (GOAD)**
Standing up a vulnerable AD lab. Domain structure, trusts, the attack surface.

**M13 — AD attacks**
Kerberoasting, AS-REP roasting, pass-the-hash, pass-the-ticket, delegation
abuse. BloodHound for attack-path mapping.

**M14 — AD detection**
Writing detections for the M13 techniques from Windows event logs. The
TGS-request pattern behind Kerberoasting, anomalous authentication, lateral
movement signatures. Coverage matrix for AD techniques.

**M15 — Post-exploitation and lateral movement**
Pivoting, tunnelling (`chisel`, SSH), credential extraction (`mimikatz`),
exfiltration — and detecting each. This is where the `ws-user01`-to-router
credential finding from Lab 05 becomes a worked detection case.

---

## Phase 5 — Cloud security *(full depth — see roadmap.md)*

Azure free tier, run as a contiguous block because trial credits expire.
*Valid as of: review at phase entry.*

**M16 — Cloud identity and access**
Entra ID, conditional access, the cloud identity attack surface.

**M17 — Cloud infrastructure security**
Network Security Groups, Key Vault, Defender for Cloud.

**M18 — Hybrid SIEM (Sentinel)**
Microsoft Sentinel, with the Azure Monitor Agent forwarding homelab VM telemetry
into it. Makes the lab hybrid — the architecture most organisations actually run
— rather than two disconnected environments.

---

## Phase 6 — Advanced monitoring

**M19 — Network IDS (Suricata)**
Signature-based network detection on the segmented lab. Writing and tuning rules;
coverage against the network techniques from earlier phases.

**M20 — Network security monitoring (Zeek)**
Behavioural network analysis and the rich connection logs Zeek produces.

**M21 — Threat intelligence integration**
Enriching alerts with external intel (VirusTotal, AbuseIPDB). IOC matching.

**M22 — Threat hunting**
Proactive hypothesis-driven hunting across the accumulated telemetry, rather
than waiting for rules to fire.

---

## Phase 7 — Incident response and forensics

**M23 — Incident response process**
Playbooks, triage, containment, the operational workflow around the tooling.

**M24 — Digital forensics fundamentals**
Disk and memory acquisition and analysis. Timeline reconstruction.

**M25 — Log analysis at scale**
Correlating across sources to reconstruct a full attack chain end to end.

---

## Phase 8 — Specialised domains

**M26 — OT/ICS security** *(full depth — see roadmap.md)*
OpenPLC + ScadaBR on a new `intnet-ot` segment — a fifth leg on the existing
router, applying exactly the M1 segmentation model. Modbus TCP captured with
`tcpdump`; the absence of authentication and encryption in the protocol observed
directly. That observation is the whole argument for why OT is defended by
architecture, not by protocol-level controls.

**M27 — AI for security operations, and securing AI systems**
*Valid as of: review at phase entry — fastest-moving module in the curriculum.*
Two halves of one module, built with the standard purple loop.
*Build:* an AI triage agent over real Wazuh telemetry — reads alerts by API,
enriches, drafts a triage note. (Preparatory work for this — a bridge project
building a simpler agent against a public API — can begin early; tracked
separately, not part of the thirty-module sequence.)
*Attack:* prompt injection via attacker-controlled fields in an alert (a real
vector when the agent reads a User-Agent or hostname). OWASP LLM Top 10,
over-permissioned tool access, MCP misconfiguration.
*Detect:* the controls and detections around it, coverage recorded.
Prerequisite: the SIEM (M5) and real detection rules must exist — an agent with
no telemetry to read is a demo, not an exercise.

**M28 — Container and orchestration security**
Docker and Kubernetes attack surface and monitoring, if the lab has grown to
warrant it.

---

## Phase 9 — Consolidation

**M29 — Adversary emulation (full-chain exercise)**
The capstone. Rather than isolated techniques, chain a real threat actor's
activity end to end — a documented APT campaign emulated across the whole
environment, initial access through to objective — and measure whether the
detection follows the full chain. The complete purple exercise: adversary
emulation on one side, detection coverage on the other, gaps documented.

**M30 — Commercial tooling** *(hard limit — see roadmap.md)*
*Valid as of: review at phase entry.*
Hands-on where a usable free tier exists: Splunk Free (500 MB/day indefinitely —
learning SPL properly, since the query language is the transferable skill, not
the interface). Conceptual familiarity only where none does: QRadar, CyberArk,
SailPoint. Stated as such rather than overclaimed — organisations deploying these
platforms train their own staff on them; what they hire for is the underlying
technical grounding.

---

## What this curriculum is not

It is not a certification path, and it is not a guarantee of competence. A
module listed here confers nothing until the lab is built, attacked, and
documented. Progress is measured by what runs and what is written up, not by how
far down this list the numbering has reached.

The purple framing is methodological, not a change of target: this is a defensive
analyst's portfolio, built by someone who understands attacks well enough to
detect them and proves the detection works. It is not a red-team portfolio.

*Nothing here is aspirational once it appears in a lab writeup. Until then, it is
a plan.*
