# Detection coverage

What this lab can see, what it cannot, and why. Technique identifiers follow
[MITRE ATT&CK](https://attack.mitre.org/).

This file is cumulative. Rows are added as techniques are attempted and move
between states as detection is built. A row marked **not covered** is not a
gap to be embarrassed about — it is a gap that has been measured, which is the
point of keeping the matrix at all.

*Last updated: 2026-08-20 · Lab 06*

---

## Status definitions

| Status | Meaning |
|---|---|
| **Detected** | A rule fires on the technique, verified with live traffic — not only `wazuh-logtest` |
| **Partial** | Detection works under some conditions and demonstrably fails under others |
| **Not covered** | The technique is present in the environment and produces no alert |
| **Out of scope** | The technique does not apply to this environment |

Verification means the technique was executed deliberately and the alert was
observed in `alerts.log`. A rule that passes `wazuh-logtest` but has never fired
on real traffic is not counted as detected — the two are different claims.

---

## Coverage

| Technique | Name | Tactic | Status | Rule | Verified |
|---|---|---|---|---|---|
| T1046 | Network Service Discovery | Discovery | **Detected** | 100100 (level 8) | 2026-08-19 |
| T1046 | Network Service Discovery — repeated, same source | Discovery | **Detected** | 100101 (level 10) | 2026-08-19 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | **Detected** | 100102 (level 10) | 2026-08-20 |
| T1070.002 | Clear Linux or Mac System Logs | Defense Evasion | **Partial** | — | 2026-08-20 |
| T1078 | Valid Accounts | Persistence / Lateral Movement | **Not covered** | — | — |

---

## Notes on individual rows

### T1046 — Network Service Discovery

Two rules cover this at different granularities. Rule 100100 fires on any
blocked connection toward the management segment; rule 100101 correlates six of
those from one source within sixty seconds and raises the level.

The pair exists because of an observation, not a design guess: a single `nc -z`
produces **three** alerts from rule 100100, because TCP retransmits the SYN when
nothing answers. Without correlation, a six-port scan would generate eighteen
individual alerts and no summary. The threshold of six was chosen from that
measured retransmission rate.

Both alerts still fire — Wazuh does not suppress the individual rules when a
composite one matches. Suppressing them means dropping 100100 to level 0, which
would cost the per-port detail. That trade-off has not been made.

### T1562.001 — Impair Defenses

Rule 100102 escalates Wazuh's built-in rules 504, 505 and 506 from level 3 to
level 10. Those three distinguish an agent that *disconnected* (went silent),
was *removed* (deleted from the manager), and was *stopped* (shut down cleanly).
An adversary using `kill -9` or cutting the network produces the first; one
using `systemctl stop` produces the third. Covering only one leaves a gap.

**Known false positive:** restarting an agent for maintenance produces the same
alert as an adversary disabling it. This happened during the lab itself, on
`mgmt-01`, while editing its configuration. The detection cannot distinguish
maintenance from tampering; in production that is handled with suppression
windows, not with a better rule.

### T1070.002 — Clear Linux or Mac System Logs

**Partial, and the reason is the most useful finding of this lab.**

Truncating a session log with `: > file` destroys its contents without root and
leaves no trace in any log the SIEM collects. Five auditd rule variants were
attempted to capture it — directory watch, `-F dir=` with an `O_TRUNC` bit mask,
`-F path=` on a specific file, `truncate`/`ftruncate` syscalls, and an unfiltered
`openat` rule. None captured the operation.

`strace` confirmed the syscall is `openat(..., O_WRONLY|O_CREAT|O_TRUNC)` and
that it succeeds. `tail -f` on the raw audit log confirmed auditd was writing
events normally throughout. The subsystem was working; the event was simply not
being generated for that invocation.

The distinguishing test: the **same truncation** run as `sh -c ': > file'` **is**
recorded, while typed directly into an interactive bash session it is not.
Identical operation, identical result on disk, different visibility.

    audit(1787218183.260:307): name=".../vboxuser-20260817-213617-933.log"
        inode=792907 OUID="vboxuser"     ← sh -c, captured
    (no corresponding record)            ← interactive bash, not captured

Generalised: **syscall-based detection depends on how an action is invoked, not
only on what it does.** An adversary aware of that difference chooses the
invocation that produces no event.

**Second approach: Wazuh FIM.** File integrity monitoring compares checksums
rather than auditing syscalls, so it should be indifferent to how the change was
made. It was enabled on the directory with `realtime="yes"` to test that.

It detects changes. It is also unusable:

    287 alerts in ~20 minutes
      0 corresponding to a truncation
    All from .timing files of active sessions writing normally

`script` writes continuously while any session is open, so every keystroke
produces a modification event. The signal-to-noise ratio was not poor — it was
zero. The one event worth seeing never surfaced above the traffic generated by
ordinary use.

A detection with a 100% false positive rate is not a degraded detection; it is a
noise source with a detection's name. It was removed after the test.

The status is *partial* rather than *not covered* because the detection works
against a scripted truncation, which is the more common case in automated
tooling — and because the boundary is now measured rather than assumed. Two
approaches were tried and both failed, for different reasons: one cannot see the
event, the other cannot distinguish it.

**Third approach considered and rejected: `tlog`.** The underlying weakness is
not that the truncation goes undetected — it is that `script` writes only to
local files, so the evidence never leaves the host it is meant to protect.
`tlog` records to structured JSON and ships to syslog, which would place session
recordings in the SIEM alongside everything else and make local destruction
largely irrelevant. It would also close the terminal-escape hazard, since
control sequences in JSON are data rather than bytes a terminal acts on.

It is not packaged for Debian (`apt-cache policy tlog` finds no candidate).
Building from source would mean installing a toolchain on the bastion and
maintaining a binary outside the package manager — no security updates, no
provenance — on the one host in the environment kept deliberately minimal. The
cure costs more attack surface than the disease.

Recorded as evaluated and rejected with reasoning rather than left as an
unexplored option.

**Compensating control:** rule 100102 covers the adjacent scenario. An adversary
who tampers with monitoring by stopping the agent is detected even though one who
quietly truncates a file is not. That is not equivalence, but it narrows the gap
by watching for the absence of data rather than for the act of destroying it.

### T1078 — Valid Accounts

Not covered, and carried from Lab 05. Two findings sit here:

`ws-user01-to-router` was a valid administrative credential for the router,
installed on a USERS-segment host and discovered during the Lab 05 credential
inventory. It has since been revoked, but nothing would have alerted on its use.

`alexis@windows` remains authorised on both the router and `ws-user01` — a path
that bypasses the bastion entirely and leaves no trace on it. Accepted as a
recovery route, since the Windows host runs the hypervisor and already controls
every VM, but it is an unmonitored administrative path by definition.

Detecting authentication by an unexpected key is the natural next rule. Wazuh's
sshd decoder extracts the key fingerprint (visible as
`Accepted publickey ... ED25519 SHA256:...`), so the data is present.

---

## What the matrix does not say

Coverage is not the same as security. Every row above describes whether an
*alert* fires, not whether the technique would *succeed*. The management segment
is protected by a default-deny firewall regardless of whether rule 100100 exists;
the rule adds visibility, not the control.

Nor does a detected row mean detected under all conditions. T1070.002 is the
explicit case, but the same caveat applies elsewhere: rule 100100 fires on
traffic toward `10.10.99.0/24` and would miss the same scan aimed at a segment
not covered by that filter.
