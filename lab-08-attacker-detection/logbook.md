# Logbook — Lab 08: Attacker machine and paired detection

---

## Session 8 — Kali in the DMZ, five detections, and tuning by measurement

**Date:** 2026-09-14 → 2026-09-16
**Duration:** ~6 h
**Module:** 6 — First victim machine + paired detection

### Objective

Add an attacker to the environment and run the first full purple cycle: attack for real, observe the telemetry the attacks produce, and write detections from what is actually there. Every rule to be validated by executing the matching attack, not by pasting a log line into `wazuh-logtest`.

### Steps performed

1. Kali prebuilt VM imported, placed in `intnet-dmz`, addressed at `10.10.30.20`, renamed `attacker-01`.
2. Segmentation tested from the attacker's side — DMZ confirmed isolated from USERS and SERVERS.
3. DMZ → SERVERS opened on port 80 only, as a documented lab exception, and persisted.
4. Rule 100103 written from the blocked DMZ probes; rules 100104, 100105, 100106 written from live scans.
5. Port-scan alert flood measured and reduced across two tuning iterations.
6. Custom decoder for the web User-Agent attempted and abandoned; cause identified and cited.
7. Rules validated with positive and negative controls against real attacks.

### Result

Five detection rules covering network and application layers, each fired by a real attack and mapped to ATT&CK. A port-scan flood of 45,397 alerts reduced to 1. One platform limitation documented with an upstream reference. The environment is a working purple-team lab rather than a telemetry collector.

---

### Failures and diagnosis

Failure numbering continues from [`lab-07-windows-endpoint`](../lab-07-windows-endpoint/), which ended at 48.

#### Failure 49 — Kali adapter left on NAT; not in the segment at all

**Symptom:** `attacker-01` had no route to the gateway; `Destination Host Unreachable`.

**Diagnosis:** the prebuilt Kali image ships with its adapter on NAT, and the change to internal networking had never been made:

    VBoxManage showvminfo "kali-dmz" --machinereadable | Select-String "^nic1="
    → nic1="nat"

**Fix:** switch to the internal network, matching the segment name exactly:

    VBoxManage modifyvm "kali-dmz" --nic1 intnet --intnet1 "intnet-dmz"

**Takeaway:** a prebuilt VM comes with its own assumptions, and NAT is the default for a reason unrelated to this lab. The name had to match `intnet-dmz` character for character — the same class of error as Failure 18, where a mismatched internal-network name created an isolated segment silently.

#### Failure 50 — Repeated timeouts, each a powered-off VM

**Symptom:** `nc` from Kali to `srv-web:80` timed out even after the firewall rule was in place.

**Diagnosis:** the rule was correct and the target was off. With the rule permitting the traffic, the packet passed the router and died at a server that was not running — which reads as a timeout, not the RST that a blocked packet would produce.

    VBoxManage list runningvms   → srv-web absent

**Takeaway:** this recurred throughout the project and is worth stating as a pattern. `refused` means something rejected the packet; `timeout` after a firewall rule is opened usually means nothing is listening — often a powered-off VM, not a firewall problem. Checking `runningvms` before diagnosing the network saved time once the pattern was recognised.

#### Failure 51 — The blocked attacker generated no alert

**Symptom:** Kali's blocked probes toward USERS and SERVERS produced nothing in the SIEM.

    grep -c '10.10.30.20' /var/ossec/logs/alerts/alerts.json   → 0

**Diagnosis:** the router logged the drops correctly, but rule 100100 only matched destinations in `10.10.99.0/24` — the management segment. A scan from the DMZ toward SERVERS or USERS had no rule covering it.

**Fix:** rule 100103, matching any `FWD-DROP` sourced from the DMZ.

**Takeaway:** this is the blind spot the Lab 06 coverage matrix had already named — 100100 fires on traffic toward the management segment and *"would miss the same scan aimed at a segment not covered by that filter"*. A real attacker demonstrated it. A detection written for one path does not generalise to others, and the matrix is where that gets tracked before an attacker finds it.

#### Failure 52 — 45,397 alerts from a single port scan

**Symptom:** `nmap -p-` against `srv-web` produced tens of thousands of level-10 alerts from rule 100103.

    grep -c '"id":"100103"' /var/ossec/logs/alerts/alerts.json   → 45397

**Diagnosis:** one alert per blocked port, times TCP SYN retransmissions. The rule worked exactly as written; the problem was that "exactly as written" is unusable at scan scale. Disk usage went from ~4 GB to 16 GB on the one scan.

**Fix:** a correlation rule (100104) collapsing ten blocked attempts from one source in thirty seconds into a single alert.

**Takeaway:** a rule that fires per-packet is a liability, not a detection — it drowns the analyst and fills the disk, and an attacker can trigger it deliberately to blind the SIEM. The fix is the same correlation pattern used for the management-segment scan in Lab 06.

#### Failure 53 — The correlation rule then flooded at level 12

**Symptom:** rule 100104 fired repeatedly during a scan — dozens of level-12 alerts instead of one.

**Diagnosis:** a correlation rule re-fires each time its frequency window is satisfied. Under a port scan the window fills many times per second, so "10 in 30 seconds" was true continuously and the rule kept alerting.

**Fix:** the `ignore` attribute, which suppresses re-firing from the same source for a set period:

    <rule id="100104" level="12" frequency="10" timeframe="30" ignore="300">

**Takeaway:** the first fix created a second problem one severity level up. Tuning is rarely a single change — it is iteration, and this is the clearest example in the project: 45,397 → ~3,000 → 1, each number measured against a real scan. Correcting noise at one level while generating it at another is the normal shape of tuning, not a mistake to be embarrassed by.

#### Failure 54 — Custom decoder never triggered, four variants deep

**Symptom:** a custom decoder to extract the web User-Agent as a field produced no field, across four regex attempts, with `wazuh-analysisd -t` passing each time.

**Diagnosis:** stopped guessing after the fourth attempt and read the documentation and the source. Wazuh evaluates parent decoders sequentially and, once one matches, considers only its children — it does not continue through the ruleset. The nginx line matches `web-accesslog-domain`, which ships before any local decoder, so a sibling extracting the User-Agent never runs.

The `<order>` field also silently rejected `user_agent` at first, because only a fixed set of static field names is accepted unless dynamic naming (`http.user_agent`) is used — a constraint documented in the header of `local_decoder.xml`, which had not been read.

**Fix:** abandon the decoder; use `<match>` on the raw event instead. This is a [known open issue](https://github.com/wazuh/wazuh/issues/32038), reported for the Cisco IOS decoders with identical symptoms.

**Takeaway:** two lessons. First, four failed variants is the signal to stop guessing and find the mechanism — the same over-late realisation as the auditd investigation in Lab 06. Second, the documentation was in the file the whole time: the list of valid field names was in the header of the very file being edited. Reading the artefact beats iterating on it.

---

### Concepts consolidated

#### A real attacker validates segmentation in a way a config review cannot

Reading the firewall rules tells you what should be blocked. Watching Kali try to reach USERS and SERVERS and fail, with the drops logged, tells you it *is* blocked. The two are different kinds of evidence, and only the second survives contact with an adversary.

The blocked probes were also the source material for rule 100103 — the attack came first, the detection followed from what it looked like. That is the purple cycle working as intended rather than as a slogan.

#### Opening a path is a decision that must be recorded

DMZ → SERVERS on port 80 exists so there is something to attack. In a real network that path is normally closed, precisely to contain a compromised DMZ host. Opening it — narrowly, one address and one port — is defensible for a lab; leaving it undocumented would misrepresent the design. The narrowness is what keeps the rest of the segmentation, and rule 100103, still meaningful.

#### Verified means fired by a real attack, with a negative control

Every rule here was triggered by executing the attack, not by `wazuh-logtest` on a pasted line. And the User-Agent rule was checked three ways: two different tools fired it, a normal browser did not. Without the negative control, "the rule fires" is only half the claim — a rule that fires on everything discriminates nothing.

This was also where an assumption got caught: the `|` alternation in `<match>` was asserted to work before being tested, and only a non-first list entry (`sqlmap`, not `nmap`) actually proved it. The habit of asking "how do I know this worked" is the through-line of the whole project.

#### Tuning happens in orders, and each order is measurable

45,397 → ~3,000 → 1. The correlation rule handled the first order of magnitude and introduced a second problem; suppression handled that. Each stage was counted against a real scan, so the tuning is defensible with numbers rather than asserted.

A threshold is an environment-specific judgement, not a universal value. Wazuh's stock web-scan rule uses 14 errors in 90 seconds — right for a public server, wrong for a lab where nobody browses. Lowering it to four is correct here and would be wrong in production. That the right number depends on the environment is what makes tuning a matter of judgement.

#### A per-packet detection is a weapon against its own SIEM

The first version of the port-scan rule turned one `nmap` into 45,397 alerts and 12 GB of disk. An attacker who knows this can scan purely to fill the indexer and stop it accepting events — hiding real activity under a flood of their own making. The detection has to summarise, not enumerate, or it becomes the vulnerability.

#### Behavioural detection outlasts signature detection

The User-Agent rule (100106) is trivially evaded — one nmap flag rewrites the string and the rule goes blind. The path-scanning and port-scanning rules (100105, 100104) watch what the attacker *does*, not what they *declare*, and cannot be sidestepped by changing a label. Both have their place: the cheap signature catches the careless, the behavioural rule catches the rest. Documenting the signature rule as low-confidence is part of using it honestly.

#### Read the artefact before iterating on it

The decoder investigation failed four times before the mechanism was found — and the constraint that broke the first attempt (valid field names) was written in the header of the file being edited. The one that broke the rest (decoder precedence) was in the documentation and in an open issue. Iterating on a guess is slower than reading how the thing works, and this is the second time in the project that lesson arrived late.

### Outstanding

- [ ] Collect evidence — the four web rules, the DMZ firewall rule, the nginx log with nmap's probes, and the alert-count progression
- [ ] **Actually attack `srv-web`.** Port 80 is open but only reconnaissance has run against it. No exploitation of the web service itself, which is the point of having opened the path
- [ ] Detections are network- and access-log-based. Request bodies and application-layer attacks (SQLi, XSS payloads) are invisible without a network IDS — Suricata, scheduled for M19
- [ ] The User-Agent rule is signature-based and evadable. Documented as low-confidence, but a behavioural web-scan detection would be stronger
- [ ] Carried forward and still open: rotate the Wazuh `admin` password (plaintext since Lab 06), re-register agents with source IPs instead of `IP: any`, and decide on `alexis@windows`
