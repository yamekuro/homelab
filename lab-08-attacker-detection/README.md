# Lab 08 — Attacker machine and paired detection

Continuation of [`lab-07-windows-endpoint`](../lab-07-windows-endpoint/). By the end of Lab 07 the environment produced telemetry from six agents but had never been attacked — every rule so far had been tested with a hand-crafted `nc` or a pasted log line.

This lab adds a Kali machine in the DMZ and closes the loop: attack the environment for real, watch what the attacks look like in the telemetry, and write the detections from what is actually there rather than from what was assumed. It is the first full purple cycle in the project — build, attack, detect, measure — and the first time the detections were shaped by real attacker behaviour.

Five rules were written and every one was validated by running the matching attack, not by `wazuh-logtest` alone.

## What it demonstrates

| Capability | Mechanism |
|---|---|
| Attacker platform in the DMZ | `attacker-01` (Kali), `10.10.30.20` |
| Segmentation verified against a real attacker | DMZ cannot reach USERS or SERVERS; proven, not assumed |
| Deliberate, minimal firewall opening | DMZ → SERVERS on port 80 only, documented as a lab exception |
| Network-layer detection | Rules 100103, 100104 — blocked traffic and correlated port scans |
| Application-layer detection | Rules 100105, 100106 — path scanning and scanner User-Agents |
| Alert volume controlled by tuning | 45,397 alerts from one scan reduced to 1 |
| A platform limitation found and documented | Wazuh decoder precedence, with an upstream issue to cite |

## The attacker, and what the segmentation did

`attacker-01` was placed in the DMZ — the zone representing a foothold an external attacker has already gained. Before opening anything, the segmentation was tested against it:

    kali$ nc -z -w2 10.10.20.50 80    → timeout
    kali$ ping 10.10.10.10            → unreachable

Both blocked. Six labs of default-deny confirmed by an actual adversary trying to cross it, and the attempts logged on the router:

    FWD-DROP: IN=enp0s10 OUT=enp0s9 SRC=10.10.30.20 DST=10.10.20.50 DPT=80 SYN
    FWD-DROP: IN=enp0s10 OUT=enp0s8 SRC=10.10.30.20 DST=10.10.10.10 ICMP

That blocked traffic was the first finding: it reached the firewall and was dropped, but the SIEM generated no alert for it. Rule 100100 only watched the management segment; nothing covered a scan from the DMZ toward the rest of the environment. A real attacker was probing the network and the detection was blind to it — the exact blind spot the Lab 06 coverage matrix had predicted in writing.

## Opening a path, deliberately

For the lab to have a reachable target, DMZ → SERVERS was opened on port 80 only:

    nft insert rule ip lab-filter forward position N \
      iifname "enp0s10" oifname "enp0s9" ip daddr 10.10.20.50 tcp dport 80 counter accept

This is a decision, not a default. In a real network, DMZ → internal is normally blocked precisely to contain a compromised DMZ host. It is opened here to create something to attack and detect, and it is opened as narrowly as possible: one source zone, one destination address, one port. Everything else from the DMZ stays blocked — which is what keeps rule 100103 firing on the rest of Kali's activity, and keeps USERS untouched as a control group the attacker cannot reach.

## The detections

Five rules, each written from an observed attack.

**100103 — Blocked traffic from the DMZ, level 10.** Any `FWD-DROP` originating in the DMZ. That zone is where the attacker lives; traffic leaving it toward other internal segments is suspicious by definition. Written from the blocked probes above — a real event, not a synthetic one. Mapped to T1046.

**100104 — Correlated port scan from the DMZ, level 12.** An `nmap -p-` against `srv-web` produced **45,397** alerts from rule 100103 — one per blocked port, multiplied by TCP retransmissions. That is not a working detection; it is a denial-of-service against the analyst, and against the SIEM's own storage. This rule correlates ten blocked attempts from one source in thirty seconds into a single alert, with `ignore="300"` to suppress repeats.

**100105 — Web path scanning, level 10.** Wazuh already has a rule for multiple 404s (31151), but its threshold is 14 in 90 seconds — tuned for a public server where stray 404s are constant. In this environment, where nobody browses, four 404s from one source in a second is unambiguous reconnaissance. Rule 100105 is a child that lowers the threshold to match what the environment actually looks like. Mapped to T1595.002.

**100106 — Scanner identified by User-Agent, level 12.** Tools announce themselves: `nmap`, `sqlmap`, `nikto` and others put their name in the User-Agent. This rule matches those strings on any 400-series web event. It is the cheapest possible detection and also the most easily evaded — one flag changes the User-Agent — which is exactly why it is documented as low-confidence and paired with the behavioural rules above.

## Tuning is the work, and it took two orders

The port-scan detection was not solved in one step. It was solved in three, each measured:

| Detection state | Alerts per scan |
|---|---|
| Rule 100103 alone (level 10) | 45,397 |
| + correlation rule 100104 (level 12) | ~3,000 |
| + `ignore="300"` suppression | 1 |

The correlation rule fixed the level-10 flood and created a level-12 flood in its place — the rule re-fired every time its window filled, which under a port scan is many times per second. The `ignore` attribute fixed that. Getting tuning right on the first try is rare; the normal case is iteration, and the iteration is recorded here with numbers.

The storage cost was real and measurable: a single `nmap -p-` grew the SIEM's disk usage from roughly 4 GB to 16 GB. Three or four such scans would fill the 40 GB partition and stop the indexer accepting events — a scan used deliberately as a way to blind the SIEM by drowning it. That is not hypothetical; it is what the first version of the rule enabled.

## Verification

Every rule was fired with a real attack and confirmed in `alerts.json`. The web path-scan rule is the clearest example — the correlation triggers on exactly the fourth 404:

    10:08:48.935  31101   5   /admin
    10:08:48.981  31101   5   /login
    10:08:48.981  31101   5   /phpadmin
    10:08:48.982  100105  10  /.git      ← correlation fires on the fourth
    10:08:48.982  31101   5   /backup

And the User-Agent rule was checked with a positive *and* a negative control, because a rule that fires on everything is as useless as one that never fires:

    "Nmap Scripting Engine..."   → 100106  level 12
    "sqlmap/1.7..."              → 100106  level 12     (a non-first list entry, proving the alternation works)
    "Mozilla/5.0 ... Chrome"     → 31101   level 5      (does not fire — the rule discriminates)

## The decoder that could not be written

The intended design for the User-Agent rule was cleaner: extract the User-Agent as a named field with a custom decoder, so it could be queried and grouped rather than string-matched. It could not be done.

Wazuh evaluates decoders sequentially and stops at the first parent that matches, then only considers that decoder's children. The nginx access log matches `web-accesslog-domain`, which ships before any custom decoder and consumes the line — a later sibling that extracts the User-Agent never runs. Four regex variants failed for this reason, not because the patterns were wrong.

This is a known limitation with an [open issue in the Wazuh repository](https://github.com/wazuh/wazuh/issues/32038) describing the identical problem for the Cisco IOS decoders. The only workarounds are to edit the shipped ruleset — reverted on every update — or to use `<match>` on the raw event. The `<match>` rule is therefore the correct solution on this platform, not a shortcut, and the field-extraction approach is recorded as blocked with a citable cause.

## Contents

    lab-08-attacker-detection/
    ├── README.md
    ├── logbook.md
    ├── configs/                        [pending collection]
    │   ├── local_rules-web.xml          Rules 100103–100106
    │   ├── nftables-dmz-rule.txt        The DMZ → SERVERS port-80 opening
    │   └── attacker-network.txt         Static addressing on attacker-01
    └── logs/                           [pending collection]
        ├── nmap-access-log.txt          nginx log showing nmap's User-Agent probes
        ├── portscan-alert-counts.txt    The 45,397 → 1 progression
        └── web-pathscan-correlation.txt The fourth-404 trigger above

## Status and continuation

The environment is now a working purple-team lab: an attacker, a monitored target, and detections written from real attacks rather than assumptions. Seven custom rules in total across Labs 06 and 08, every one validated by execution, every one mapped to ATT&CK.

Two threads are open for the next lab. The port-80 opening exists so `srv-web` can be attacked properly, but so far only reconnaissance has been run against it — no exploitation of the service itself. And the detections so far are network- and access-log-based; the richest attacks against a web server live in request bodies and application logs, which is where a network IDS (Suricata, scheduled for a later module) would add a layer this lab does not have.

**Coverage:** the [coverage matrix](../coverage.md) records the five techniques these rules address and the one that remains a documented gap. It is updated as part of closing this lab.
