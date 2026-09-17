# Lab 07 — Windows endpoint and Sysmon telemetry

Continuation of [`lab-06-siem`](../lab-06-siem/). That lab produced a working SIEM with five agents, three detection rules, and a coverage matrix. It also produced a gap worth naming: every host in the environment ran Debian, and most SOC work does not.

This lab adds a Windows endpoint to the USERS segment, instruments it with Sysmon, and gets its telemetry into the SIEM. The rules come later — this is about having something worth writing rules against.

## What it demonstrates

| Capability | Mechanism |
|---|---|
| Windows host in the user segment | `ws-user02`, Windows 11, `10.10.10.20` |
| Process-level visibility | Sysmon with the SwiftOnSecurity configuration |
| Windows telemetry reaching the SIEM | Wazuh agent reading `Microsoft-Windows-Sysmon/Operational` |
| Readable event output | `jq` filters over `alerts.json` |
| Alert triage on real events | Prioritised by impact, reconstructed by timeline |

## Why Windows

The environment was Debian-only through six labs. That is a coherent design — the router, the bastion, the web server and the SIEM are all better as Linux — but it left a blind spot: no Windows event logs, no Sysmon, no process telemetry of the kind most enterprise detection is built on.

Comparing against published home SOC labs made the gap concrete. Nearly all of them include a Windows endpoint with Sysmon, usually alongside an Active Directory domain. The detection techniques that matter for employability — process ancestry, encoded PowerShell, credential access — have no Linux equivalent.

`ws-user02` sits in USERS rather than SERVERS because it represents a workstation, and because USERS is where a compromised endpoint would realistically be.

## What Sysmon adds

Windows logs that a process started. Sysmon logs which process, launched by what, with which arguments, from where, and with what hash:

    Image:             C:\Windows\SysWOW64\net.exe
    CommandLine:       net user
    ParentImage:       C:\Program Files (x86)\ossec-agent\wazuh-agent.exe
    ParentCommandLine: "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe"
    User:              NT AUTHORITY\SYSTEM
    IntegrityLevel:    System
    SHA256:            E7A3A04DB13F7D5E65DB45DBED99B80C9AD9907BEEBA3416E2E5428E1EFB791E

The parent field is what makes detection possible. A `powershell.exe` launched by `explorer.exe` is a user running a script; the same binary launched by `winword.exe` is a macro, and that distinction is the basis of a large share of endpoint detections.

Sysmon ships with almost nothing enabled by default. The configuration used here is the SwiftOnSecurity template — roughly 1,200 lines that decide what to capture and, more importantly, what to ignore. Installing Sysmon without a configuration produces very little; the configuration is the product.

## Getting the telemetry to the SIEM

Two steps, and the second is easy to miss.

The Wazuh agent installs from an MSI with the manager address passed as a property. That failed silently here — the installed configuration showed `<address>0.0.0.0</address>` and the service would not start, because it was trying to reach an invalid address. The agent name was not applied either, so the first successful registration arrived as `DESKTOP-SPISV7K` rather than `ws-user02`.

Once connected, the agent still does not read Sysmon. Its default sources are the Security, System and Application logs; the Sysmon channel is separate and must be declared:

    <localfile>
      <location>Microsoft-Windows-Sysmon/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>

`eventchannel` is the format for modern Windows channels, distinct from the older `eventlog`. Without this block the agent reports normally and the detailed process telemetry stays on the machine — an agent that looks healthy and delivers almost nothing.

## Reading what arrives

Raw `alerts.log` is single-line JSON and effectively unreadable. `jq` over `alerts.json` turns it into something a person can scan:

    sudo tail -20 /var/ossec/logs/alerts/alerts.json | \
      jq -r '[.timestamp, .agent.name, .rule.level, .rule.description] | @tsv'

And filtering by level surfaces what matters:

    jq -r 'select(.rule.level > 5) | [.timestamp, .agent.name, .rule.level, .rule.description] | @tsv'

In a steady state the environment produces almost nothing above level 3 — logins, `sudo`, log rotation. That baseline is itself useful: it is what "normal" looks like, and it is the reference against which anything unusual is judged.

## A triage walkthrough

Three alerts arrived within minutes of each other:

    ws-user02   9   Powershell process created an executable file in Windows root folder
    lab-router  10  Repeated attempts toward the management segment - possible scan
    mgmt-01     3   Successful sudo to ROOT executed

The instinct is to open the level 10 first. That is the wrong order.

The level 10 was a **blocked** scan — the firewall stopped it, so nothing happened. The level 9 was PowerShell writing an executable, which **succeeded**. And the level 3, the lowest of the three, was privilege escalation on the bastion — the host that administers every other machine in the lab.

Priority follows impact, not severity number. Blocked versus successful matters more than the level, and the level does not tell you which is which.

Investigating the `sudo` meant reconstructing a sequence rather than reading an event:

    12:40:04  192.168.0.129  vboxuser  sshd: authentication success
    12:40:04  -              vboxuser  PAM: Login session opened
    12:46:00  -              root      Successful sudo to ROOT executed

Source address, user, and a six-minute gap between login and escalation. Expected origin, expected user, working hours, plausible interval — legitimate administrative activity. Most triage ends this way, and "nothing happened" is a valid conclusion when it is reached by evidence.

The command itself closes it:

    sudo tail -200 /var/ossec/logs/alerts/alerts.json | \
      jq -r 'select(.rule.id=="5402") | [.timestamp, .agent.name, .data.command] | @tsv'

Rule 5402 is Wazuh's "successful sudo to ROOT". The output was a full reconstruction of the session — twenty-five privileged commands across three machines, including edits to the SIEM's own detection rules.

Read without context, that is exactly what an intrusion looks like.

## Verification

| Test | Result |
|---|---|
| `Get-Service Sysmon64` | `Running` |
| Sysmon event count at baseline | 21 events on a freshly installed, idle host |
| `Get-Service WazuhSvc` | `Running` after correcting the manager address |
| `agent_control -l` on `siem-01` | `ws-user02` Active |
| Agent log | `Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'` |
| Sysmon events in `alerts.json` | Process Create events with full command line, parent and hash |

The 21-event baseline is worth keeping. Lab 05 measured memory only after purging a desktop and could not state a delta; here the starting point was recorded before the machine did anything.

## Contents

    lab-07-windows-endpoint/
    ├── README.md
    ├── logbook.md
    ├── configs/                        [pending collection]
    │   ├── sysmonconfig.xml            SwiftOnSecurity template as deployed
    │   ├── ossec-agent-conf.xml         Agent config with the Sysmon channel
    │   └── network-config.txt          Static addressing on ws-user02
    └── logs/                           [pending collection]
        ├── sysmon-process-create.json  A decoded Sysmon EID 1 event
        └── triage-sudo-sequence.txt    The reconstructed sudo timeline

## Status and continuation

The environment has Windows telemetry. `ws-user02` reports process creation, network connections and registry activity through Sysmon, and the agent delivers it to the SIEM alongside everything else.

No detection rules were written here. That is deliberate: there was nothing to detect yet. The host generates telemetry and the triage walkthrough above exercised reading it, but the rules wait for something worth catching.

**Lab 08:** add an attacker. A Kali machine in the DMZ turns the environment from one that produces telemetry into one that produces attacks — and the detection rules follow from what the attacks actually look like, rather than from what they were assumed to look like.
