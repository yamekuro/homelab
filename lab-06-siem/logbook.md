# Logbook — Lab 06: SIEM deployment and first detections

---

## Session 6 — SIEM segment, Wazuh deployment, agents, and the first detection rules

**Date:** 2026-08-17 → 2026-08-20
**Duration:** ~1.5 d
**Module:** 5 — Log centralisation

### Objective

Give the environment a SIEM. Build a dedicated segment for it, deploy Wazuh, get agents reporting from every host, and write the first detection rules against the lab's own telemetry. Then test the premise that motivated it: whether centralising events resolves the Lab 05 finding that host-local logs can be destroyed by the user they audit.

### Steps performed

1. Sixth router leg added from the host CLI, configured as `seg-siem` on `10.10.40.1` with IPv6 disabled from creation.
2. Egress rules for the segment — 53, 80 and 443 only — inserted before the terminating drop and persisted.
3. `siem-01` installed at `10.10.40.10`; GNOME purged following the Lab 05 procedure.
4. Wazuh 4.14.7 deployed all-in-one after two failed attempts.
5. Firewall rules added for bastion administration (22), dashboard access (443) and agent reporting (1514, 1515).
6. Dashboard reached by SSH port-forward through the bastion rather than by exposing the port.
7. Agents installed on `srv-web`, `ws-user01`, `mgmt-01` and `lab-router`; five active including the manager's own.
8. Rules 100100, 100101 and 100102 written, verified with `wazuh-logtest`, then fired with real traffic.
9. Truncation detection attempted with auditd and with FIM; both approaches characterised and rejected.
10. Coverage matrix written to [`coverage.md`](../coverage.md) in the repository root.

### Result

Five agents reporting into a SIEM on its own segment, reachable only through the bastion. Three detection rules firing on deliberately generated activity, each mapped to a MITRE technique. One technique attempted and not covered, with the boundary measured rather than assumed.

---

### Failures and diagnosis

#### Failure 38 — Two Wazuh installations failed, and the first error message pointed at the wrong thing

**Symptom:** the installer ran to completion and rolled itself back. `systemctl status` found no units afterwards.

**First diagnosis, incomplete:** the log's only ERROR line read `User wazuh is not registered in Wazuh API`, twenty-nine seconds after the indexer cluster had reached GREEN. The obvious reading was a timing problem — the script querying the manager's API before it had finished starting.

**Second attempt, real cause:**

    curl: (22) The requested URL returned error: 429
    ERROR: Error downloading wazuh-template.json file.

HTTP 429 is rate limiting. Two full installations inside fifteen minutes, each pulling hundreds of megabytes, and the Wazuh package servers began refusing. Waiting an hour and re-running the identical command succeeded.

**Note on a red herring:** the installer warns that Debian is not among its recommended systems, and that warning was the leading suspect for a while. It was not the cause. Everything platform-specific worked; the failure was a download quota.

**Takeaway:** the first error message a tool reports is not necessarily the first thing that went wrong. The API error in attempt one was almost certainly a downstream effect of the same rate limiting, surfacing differently. Reading one log line and acting on it would have led to reinstalling the VM with Ubuntu — a large change for a problem that resolved itself with time.

The rollback deserves credit: Wazuh removed every package and directory it had installed, twice, leaving no residue. An installer that reverts cleanly is worth more than one that succeeds more often.

#### Failure 39 — GNOME installed on `siem-01` despite selecting a minimal install

**Symptom:** the SIEM booted into a desktop.

**Cause:** the same trap as Failure 26 — the Debian installer's software selection screen has the desktop environment checked by default.

**Consequence and decision:** unlike `mgmt-01`, nothing had been invested in this VM yet, so reinstalling was the cheaper option in principle. The purge was chosen instead, and it went cleanly: the procedure from Lab 05 was followed exactly — `apt-mark manual` on `sudo`, `network-manager`, `openssh-server` and the running kernel; `set-default multi-user.target`; simulation read in full; positive control on the filter before executing.

**Takeaway:** 1571 → 1412 packages and 159 removed, **identical to `mgmt-01`**. Same ISO, same selections, same purge command, same result. Two machines built the same way converge on the same package set, which is a small argument for reproducibility being achievable even by hand.

The wider lesson is about recurrence: this trap has now caught three of five machines, and it was known about after the first. Knowing a failure mode is not the same as having internalised it.

#### Failure 40 — The dashboard was unreachable because the firewall had no rule for port 443

**Symptom:** the SSH tunnel established correctly (`lsof` showed 8443 listening on the Mac) and the browser reported the site could not be reached.

**Diagnosis by layer:**

    mgmt-01$ curl -k -sI https://10.10.40.10   → HTTP/1.1 302 Found, osd-name: siem-01
    mgmt-01$ nc -z -v 10.10.40.10 443          → timeout

The dashboard was serving. The bastion could not reach it. The forward rule permitted MGMT toward the four segments on **port 22 and ICMP only** — 443 had never been opened, and every previous interaction with `siem-01` had been over SSH, so the gap had not surfaced.

**Fix:** a rule specific to the path rather than widening the existing one:

    nft insert rule ip lab-filter forward position 17 \
      iifname "enp0s16" oifname "enp0s17" ip daddr 10.10.40.10 tcp dport 443 counter accept

**Takeaway:** adding the port to the existing four-segment rule would have opened 443 toward USERS, SERVERS and DMZ as well, for no reason. A rule that names the source, the destination address and the single port is longer to write and does not quietly widen with time. Same reasoning as Failure 28: a new service needs its own rule, and default-deny makes no exceptions for convenience.

#### Failure 41 — The SSH tunnel died silently, twice

**Symptom:** the dashboard stopped loading with no error from SSH. `curl` to `localhost:8443` failed in three milliseconds — nothing listening.

**Cause:** a tunnel session carries no traffic while the browser is idle, so the connection is closed as inactive by the NAT engine or by sshd.

**Fix:** a keepalive in the client config, applied to every host:

    Host *
        ServerAliveInterval 30

**Takeaway:** `lsof` had shown the tunnel listening earlier, which was true at the time and stale by the time it was read. State observed a minute ago is not state now — the same class of error as checking a rule is loaded without checking it is still loaded.

#### Failure 42 — `Permission denied (publickey)` on four hosts at once, and nothing was wrong

**Symptom:** a status check across all four hosts failed identically:

    ssh mgmt-01 'for h in ...; do ssh $h hostname; done'
    lab-router   vboxuser@10.10.99.1: Permission denied (publickey).
    srv-web      vboxuser@10.10.20.50: Permission denied (publickey).
    ws-user01    vboxuser@10.10.10.10: Permission denied (publickey).
    siem-01      vboxuser@10.10.40.10: Permission denied (publickey).

**Diagnosis:** four hosts failing identically points at one shared cause, not four faults. Running the same command from an interactive session on `mgmt-01` worked immediately — after prompting for the key passphrase.

**Cause:** a command passed in quotes allocates no terminal on the intermediate host, so ssh cannot prompt for the passphrase, cannot decrypt the key, and has nothing to offer. The server sees a client with no usable credential.

**Fix:** load the key into an agent first. Note that `AddKeysToAgent yes` populates an agent but does not start one:

    eval "$(ssh-agent -s)"
    ssh-add ~/.ssh/id_ed25519_admin

**Takeaway:** `Permission denied (publickey)` does not always mean the credential is wrong. It can mean the credential is correct and cannot be unlocked in this context. That distinction cost a real amount of time and briefly looked like a broken environment.

#### Failure 43 — Five auditd rules, none capturing a truncation that demonstrably occurs

The longest investigation of the lab, and the one that produced the most transferable result.

**Objective:** detect `: > sessionlog` — the Lab 05 attack — via auditd.

**Attempts, in order:**

1. `-w /var/log/session-logs/ -p wa` — directory watch. Captured a `touch` (which alters the directory) and not a truncation (which alters an inode inside it).
2. `-S openat -F dir=... -F a2&0x200` — syscall rule filtering on the `O_TRUNC` bit. Loaded, never fired.
3. `-S truncate,ftruncate -F dir=...` — the dedicated truncate syscalls. Never fired; `: >` uses `openat`.
4. `-S openat -F path=<specific file>` — exact path, no directory. Never fired.
5. `-S openat -F auid=1000 -F success=1` — no path filter at all, every openat by the user. Captured hundreds of events and **not the truncation**.

**Instrumentation used to rule things out:**

    strace -f -e trace=openat,truncate,ftruncate sh -c ': > file'
    → openat(AT_FDCWD, "...", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3

    tail -f /var/log/audit/audit.log
    → events flowing normally, key="trunc_test" present

    auditctl -s
    → enabled 1, lost 0

The syscall is `openat` with `O_TRUNC` and it succeeds. auditd was writing. The subsystem was healthy. The event simply was not being produced for that invocation.

**The distinguishing test:**

    audit(1787218183.260:307): name=".../vboxuser-20260817-213617-933.log"
        inode=792907 OUID="vboxuser"        ← sh -c ': > file'   captured
    (no corresponding record)                ← : > file in bash  not captured

**Takeaway:** syscall-based detection depends on **how** an action is invoked, not only on what it does. An interactive shell can satisfy a redirect without issuing the syscall a fresh process would, and auditd audits syscalls — it cannot record what the kernel never sees. An adversary aware of the difference chooses the invocation that produces no event.

A secondary note on process: five variants were tried by approximation before reaching for `strace`. Measuring first would have been faster than guessing five times.

#### Failure 44 — FIM detects the truncation and is unusable

**Symptom:** with `realtime="yes"` on `/var/log/session-logs`, alerts began immediately:

    287 alerts in ~20 minutes
      0 corresponding to a truncation
    All from .timing files of active sessions writing normally

**Cause:** FIM compares checksums, so it is indifferent to invocation — which is exactly why it was worth trying. But `script` writes continuously while any session is open, so ordinary use generates a modification event per keystroke.

**Takeaway:** a detection with a 100% false positive rate is not a degraded detection. It is a noise source with a detection's name, and it buries the event it was deployed to find. Removed after the test.

Recorded alongside Failure 43 as two approaches to one technique, failing for opposite reasons: one cannot see the event, the other cannot distinguish it.

---

### Concepts consolidated

#### A SIEM detects only what it has been taught to detect

Firewall events arrived at the manager, were decoded correctly by a built-in decoder, and generated nothing — rule 4100 is a container at level 0. Nothing was misconfigured; that is the default, and a sensible one given how much a firewall drops in a real network.

The consequence is that a freshly installed SIEM is close to blind to anything specific to its environment. Everything environment-specific is invisible until someone writes the rule. The install is the beginning of the work, not the end of it.

#### Verified means fired on real traffic

`wazuh-logtest` validates that a rule matches a line you paste into it. That is a weaker claim than the rule firing on live activity, and the two came apart in practice: a hand-trimmed log line failed to decode because it lacked the fields between `DST=` and `PROTO=` that the decoder's regex requires. The rule was correct; the test data was not.

Every rule in this lab is recorded as verified only after the technique was executed deliberately and the alert observed in `alerts.log`. The coverage matrix keeps that distinction explicit.

#### Retransmission inflates alert counts, and the inflation is measurable

A single blocked `nc -z` produces three alerts, because TCP retransmits the SYN when nothing answers — the same backoff pattern documented in Lab 05, now arriving as duplicate alerts rather than duplicate log lines.

That measurement, not a guess, set the correlation threshold at six. Tuning decisions are defensible when they cite an observed rate; arbitrary thresholds are how alert fatigue starts.

#### Composite rules do not suppress their components

When rule 100101 fires, rule 100100 has already fired several times and those alerts remain. Wazuh generates both. Suppressing the individual ones means dropping them to level 0, which costs the per-port detail that makes a scan legible.

The trade-off is real and was not resolved — it is recorded as a decision not taken rather than a problem overlooked.

#### An agent can stop reporting in three distinguishable ways

Wazuh separates *disconnected* (went silent), *removed* (deleted from the manager) and *stopped* (shut down cleanly), as rules 504, 505 and 506. An adversary using `kill -9` or cutting the network produces the first; one using `systemctl stop` produces the third.

Covering one leaves a gap, and the gap corresponds to a different level of adversary care. Rule 100102 covers all three by listing them in a single `if_sid`.

#### Detecting absence is more robust than detecting destruction

The truncation itself resisted five auditd variants and defeated FIM by volume. What is straightforward to detect is the *consequence* — an agent that stops reporting, a source that goes quiet.

That reframing is the durable lesson from this lab. Watching for the absence of expected data sidesteps the question of how the attacker suppressed it, because every method of suppression produces the same absence.

#### Centralisation protects what it collects, and nothing else

The SIEM was built partly to resolve the Lab 05 finding. It resolves half of it: events already shipped are beyond a local attacker's reach. It does nothing for logs that were never in the collection path — `/var/log/session-logs/` was not among the agent's sources, so destroying its contents changed nothing the SIEM knew about.

Stated plainly because it is easy to assume otherwise: installing a SIEM does not make host logs tamper-resistant. It makes *collected* events tamper-resistant, and the two sets are not the same.

#### The analyst's own activity is telemetry

Every `sudo grep` run against `alerts.log` appeared in `alerts.log` moments later, complete with the command line, TTY and working directory. The investigation is as visible as the thing investigated.

Useful in two directions: an analyst's actions are auditable, and an attacker who compromises the SIEM leaves traces in the system they are trying to manipulate.

#### `auid` survives privilege escalation

Audit records carry both `uid` (who the process ran as) and `auid` (who opened the session). `sudo` changes the first and not the second, so `auid=vboxuser uid=root` attributes a root action to the human who initiated it.

That is the trace ordinary logs lose, and the reason auditd remains worth having even after Failure 43.

#### Rate limiting looks like a broken installation

Two installations in fifteen minutes triggered HTTP 429 from the package servers, and the failure surfaced as an unrelated-looking API error the first time. Nothing was wrong with the platform, the configuration, or the host.

Worth remembering when an install fails twice in quick succession: the second failure may be caused by the first attempt, not by whatever the log blames.

### Outstanding

- [ ] Collect evidence from `siem-01`, `mgmt-01` and `lab-router` — `local_rules.xml`, the five SIEM firewall rules, `agent_control -l`, listening sockets, and one alert sample per rule
- [ ] **Register agents with their source addresses.** All five show `IP: any`, meaning a stolen agent key would authenticate from any host. This is the mitigation that makes the inbound 1514 rule acceptable, and it is currently not applied
- [ ] **Rotate the Wazuh `admin` password**, which was read from `wazuh-install-files.tar` and handled in plaintext during the lab
- [ ] Decide on `alexis@windows`, present in `authorized_keys` on the router and `ws-user01` — an administrative path that bypasses the bastion and produces no record on it. Carried from Lab 05
- [ ] Consider whether `script` should be replaced. `tlog` would ship session recordings to syslog and close both the tamper gap and the terminal-escape hazard, but it is not packaged for Debian; building from source contradicts the minimal-surface standard applied to every host. Recorded as evaluated and rejected in [`coverage.md`](../coverage.md)
- [ ] Review indexer retention before the disk fills. 40 GB free at deploy; the index grows with event volume and a full indexer stops accepting events without an obvious failure
- [ ] **Add a Windows endpoint with Sysmon.** The environment is Linux-only, and most SOC work is not. Windows event logs plus Sysmon are the highest-value telemetry source missing here, and the gap is more significant than any additional Linux rule. Scheduled as M4 in the curriculum; worth pulling forward
- [ ] **Add a Kali attacker machine.** Attacks so far have been simulated with `nc -z` and single commands — enough to fire a rule written for that exact event, but not a real technique. `nmap` alone produces SYN scans, version detection and OS fingerprinting, each with a distinct signature none of the current rules has faced. Placement is a design decision in itself: DMZ simulates an external foothold, USERS simulates a compromised insider
- [ ] Decide an IPv6 filtering policy for `siem-01`. The router is covered by the `ip6` table from Lab 05; `siem-01` has IPv6 active (`[::]:22` is listening) and no equivalent policy

### Gaps identified against comparable work

A survey of published home SOC labs (2025–2026) put two absences into perspective. Both are scheduled later in the curriculum; both are worth pulling forward.

- [ ] **Windows endpoint with Sysmon.** The environment is Linux-only. Most SOC work is Windows, most detection engineering material assumes Windows telemetry, and nearly every comparable lab includes at least one Windows host with Sysmon feeding the SIEM. This is the largest single gap in the environment and the one with the clearest bearing on employability. Curriculum position: M4
- [ ] **Attacker machine (Kali).** Attacks so far have been simulated with `nc -z` and individual commands — sufficient to fire a rule that was written for exactly that input, but not an adversary. A real `nmap` scan produces SYN scans, version detection and OS fingerprinting, each with a distinct signature; the current rules have only ever met the simplest case. Without a proper attacker host the purple cycle is incomplete: the *attack* half is being approximated. Placement decision pending — DMZ models an external foothold, USERS models a compromised insider. Curriculum position: M7

The two are coupled. Kali without Windows targets means attacking only Linux; Windows without an attacker means telemetry that is never exercised.
