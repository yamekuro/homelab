# Logbook — Lab 07: Windows endpoint and Sysmon telemetry

---

## Session 7 — Windows endpoint, Sysmon instrumentation, and reading the SIEM

**Date:** 2026-09-14
**Duration:** ~4 h
**Module:** 4 — Endpoint hardening (Windows)

### Objective

Add a Windows host to the USERS segment and get process-level telemetry into the SIEM. The environment had been Debian-only for six labs, which left it without the event source most enterprise detection is built on. Secondary objective: learn to read what the SIEM produces, since a working pipeline is useless if the output is unreadable.

### Steps performed

1. `ws-user02` created in VirtualBox, attached to `intnet-users`, Windows 11 installed.
2. Static addressing configured at `10.10.10.20/24` after the adapter type was corrected.
3. Sysmon downloaded and installed with the SwiftOnSecurity configuration; baseline event count recorded.
4. Wazuh agent installed from MSI, manager address corrected by hand, agent re-registered under the right name.
5. Sysmon channel added to the agent configuration and verified in the agent log.
6. `jq` installed on `siem-01` and filters built for reading `alerts.json`.
7. Triage walkthrough on three real alerts, reconstructing the timeline around a `sudo` escalation.

### Result

Windows process telemetry arrives at the SIEM with full command line, parent process, user and binary hash. Six agents reporting. The alert stream is readable with `jq` filters, and a baseline of what normal looks like in this environment has been established — almost nothing above level 3.

---

### Failures and diagnosis

#### Failure 45 — Windows installer could not see the network adapter

**Symptom:** the Windows 11 installer stopped at the network step, unable to find a driver for the network card.

**Cause:** VirtualBox's default adapter type is not one Windows 11 recognises without additional drivers.

**Fix:** change the emulated card to an Intel PRO/1000 MT Desktop, which Windows recognises natively:

    VBoxManage modifyvm "ws-user02" --nictype1 82540EM

**Takeaway:** the installer's phrasing points at a missing driver, which invites hunting for drivers. The actual fix is to present hardware the installer already supports. Worth remembering that in a VM the hardware is a configuration choice, not a constraint.

#### Failure 46 — MSI properties silently ignored; agent installed pointing at 0.0.0.0

**Symptom:** the Wazuh service installed but would not start.

**Diagnosis:** the installed configuration showed the manager address never got applied:

    Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "<address>"
    → <address>0.0.0.0</address>

The `msiexec /q WAZUH_MANAGER="10.10.40.10" WAZUH_AGENT_NAME="ws-user02"` invocation completed without error and applied neither property. The service started, tried to reach an invalid address, and stopped.

**Fix:** edit `ossec.conf` by hand and set the address. Then, separately, re-register with the correct name:

    & "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 10.10.40.10 -A ws-user02

**Consequence of the second half:** the first successful registration arrived as `DESKTOP-SPISV7K`, the Windows default hostname, because `WAZUH_AGENT_NAME` had failed along with the address. In an inventory of six agents an auto-generated name is a real problem — it does not identify the machine without cross-referencing.

**Takeaway:** a silent installer failure is worse than a loud one. `msiexec /q` returned success while applying nothing, and the only evidence was the configuration file itself. Checking the resulting config rather than the exit code is the habit that catches this.

#### Failure 47 — Agent connected but Sysmon telemetry never arrived

**Symptom:** the agent reported as Active in `agent_control -l`, and searching the alert log for Sysmon events returned nothing.

**Diagnosis:** the Wazuh agent's default Windows sources are the Security, System and Application logs. The Sysmon channel is separate and not included.

    Select-String -Path "...\ossec.conf" -Pattern "Sysmon"   → no output

**Fix:** declare the channel explicitly, then restart the service:

    <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>

Confirmed in the agent log:

    INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'.

**Takeaway:** an agent showing Active is not an agent delivering what you assume. This is the Windows equivalent of Lab 06's finding that a SIEM detects only what it has been taught to detect — the plumbing was healthy and the valuable data was not flowing through it.

#### Failure 48 — `Invoke-WebRequest` returned 403 on a valid URL

**Symptom:** downloading the agent MSI from `packages.wazuh.com` failed with `(403) Forbidden`, for a URL that was correct.

**Attempts:** forcing TLS 1.2, overriding the user agent. Neither worked.

**Fix:** download through the browser inside the VM.

**Takeaway:** not every problem is worth solving at the level it appears. Twenty minutes into diagnosing a PowerShell HTTP client, the browser did it in thirty seconds. Knowing when to stop diagnosing is a skill in itself, and it is not the same as giving up — the objective was the file, not the understanding of why one client failed.

---

### Concepts consolidated

#### Sysmon is the configuration, not the binary

Installed with defaults, Sysmon records very little. The SwiftOnSecurity template is roughly 1,200 lines whose job is largely deciding what *not* to capture — a Windows host generates enough process activity to bury anything interesting within minutes.

That mirrors the tuning lesson from the firewall rules: the value is in what gets filtered out, not in what gets collected. A telemetry source without a filtering strategy is a noise source.

#### Parent process is what makes endpoint detection possible

A `powershell.exe` on its own says nothing. The same binary with `ParentImage: winword.exe` is a macro executing, and that is a detection.

Sysmon reconstructs process ancestry, which is why it is the foundation of Windows detection and why the Windows event log alone is not enough. The first captured event in this lab showed `net.exe` launched by `wazuh-agent.exe` launching `net1.exe` — benign, but the shape of the data is the same shape an attack would take.

#### An agent reporting is not an agent delivering

`agent_control -l` showed `ws-user02` as Active while none of its Sysmon telemetry was reaching the manager. Connectivity, authentication and heartbeat were all healthy; the channel that mattered was simply not declared.

Health checks answer "is it connected", not "is it sending what I need". The two questions have different answers and only the second matters.

#### Triage is prioritised by impact, not by severity number

Three alerts, levels 3, 9 and 10. The level 10 was a blocked scan — nothing happened. The level 3 was privilege escalation on the bastion, the host that administers everything else.

Severity encodes how unusual an event is, not how much damage it implies. Reading the description to find out whether something was *blocked* or *succeeded* changes the order entirely, and the level does not carry that information.

#### An event is not an investigation; a sequence is

The `sudo` alert on its own said nothing useful. What closed the case was the surrounding timeline: source address, user, the gap between login and escalation, and finally the command executed.

    12:40:04  192.168.0.129  vboxuser  authentication success
    12:46:00  -              root      sudo to ROOT

Four fields and two timestamps turned an ambiguous alert into a closed case. None of them were in the original alert.

#### The log does not distinguish the administrator from the attacker

Filtering rule 5402 produced a reconstruction of the session: twenty-five privileged commands across three machines, including edits to the SIEM's own detection rules and validation of the changes.

Read without knowing who ran them, that is an intruder disabling monitoring — T1562.001, the technique Lab 06 wrote a rule for. The activity is identical; only context separates them. That is why `auid`, source address and time-of-day matter more than the command itself.

#### Investigation is itself telemetry

Every `sudo grep` run against `alerts.log` appeared in `alerts.log` moments later, with command line, TTY and working directory.

Two consequences: an analyst's actions are auditable, and an attacker who reaches the SIEM leaves traces in the system they are trying to manipulate.

#### Windows is louder than a minimal Debian

The Debian hosts in this lab are near-silent at rest. `ws-user02` produces software protection service events, service startup type changes and scheduled task activity as a matter of course.

That is realistic — a workstation does these things — and it raises the baseline the SIEM has to filter. It also generated the lab's first false positive from Wazuh's own ruleset: "Powershell process created an executable file in Windows root folder", level 9, triggered by the Sysmon installation itself. A legitimate administrative action, correctly flagged as suspicious, because it looks exactly like what an attacker would do.

### Outstanding

- [ ] Collect evidence — Sysmon configuration as deployed, agent config with the channel block, a decoded EID 1 event, and the triage timeline
- [ ] **Rename the Windows host.** The computer name is still `DESKTOP-SPISV7K`; the agent is registered as `ws-user02` but Sysmon events carry the Windows hostname, so the two do not match in the SIEM
- [ ] Windows is unhardened. No Group Policy baseline, no audit policy configuration, Defender at defaults. Lab 07 added telemetry, not hardening, and the module title claims both
- [ ] Consider an Active Directory domain. Most Windows detection techniques — Kerberoasting, credential access, lateral movement — need a domain to be meaningful. Currently a standalone workstation
- [ ] Decide an IPv6 policy for `ws-user02`, consistent with the `ip6` table applied to the router in Lab 05
