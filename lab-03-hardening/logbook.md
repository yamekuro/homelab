# Logbook — Lab 03: Router hardening

---

## Session 3 — Input filtering, service binding, and surface reduction

**Date:** 2026-08-13
**Duration:** ~3 h
**Module:** 1 — Networking for security

### Objective

Close the gaps left open by Lab 02: filter traffic addressed to the router itself, stop sshd listening where it should not, make logs survive a reboot, and remove everything the machine does not need in order to be a router.

### Steps performed

1. Persistent journal: `/var/log/journal` created, `SystemMaxUse=200M` set on both VMs.
2. `input` chain created with `policy accept`, populated with five rules, verified, then switched to `policy drop`.
3. Verified that legitimate traffic still worked and that a connection to a non-permitted port was dropped and logged.
4. `ListenAddress` directives added to `sshd_config` for the three internal addresses.
5. Diagnosed and fixed the resulting boot-order failure with a systemd override.
6. Investigated 104 unexplained drops in the log, traced them to `cups-browsed`.
7. Purged the GNOME desktop environment and removed 11 unnecessary services.
8. Rebooted and confirmed every property held with no manual intervention.
9. Snapshots `sesion03-antes-purge` and `sesion03-completa`.

### Result

Router filters both `input` and `forward` with default deny and logging. sshd reachable only from internal segments. Three listening sockets in total. Drop counter at zero after a clean boot, where it had been 119.

---

### Failures and diagnosis

#### Failure 14 — `SystemMaxUse=200` without a unit

**Symptom:** journal size limit appeared not to apply.

**Cause:** the value was written as `200` rather than `200M`. Without a suffix, systemd interprets the number as **bytes**. 200 bytes is nonsensical, so the setting was effectively ignored.

**Takeaway:** a configuration value that is syntactically valid but semantically wrong produces no error. Nothing complains; the behaviour is simply not what was intended. Valid suffixes are `K`, `M`, `G` — and the general habit is to verify the effect of a setting rather than the presence of the line.

#### Failure 15 — sshd cannot bind to addresses that do not exist yet

**Symptom:** after adding `ListenAddress` and rebooting, SSH from `ws-user01` returned `Connection refused`. Not a timeout — something answered.

**Diagnosis:** `Connection refused` means the packet arrived and the kernel replied with a RST because no process was listening. A firewall drop produces silence instead. That distinction placed the fault on the service, not the filter.

    systemctl is-active ssh      → failed
    journalctl -u ssh -b:
      error: Bind to port 22 on 10.10.30.1 failed: Cannot assign requested address
      error: Bind to port 22 on 10.10.20.1 failed: Cannot assign requested address
      error: Bind to port 22 on 10.10.10.1 failed: Cannot assign requested address
      fatal: Cannot bind any address.

sshd started before NetworkManager had configured the interfaces. With none of the three addresses assigned yet, it had nothing to bind to and aborted.

**Note:** `ExecStartPre=/usr/sbin/sshd -t` exited `0/SUCCESS`. The configuration file was syntactically correct — a syntax test cannot detect a timing dependency.

**Fix:**

    sudo systemctl edit ssh.service
      [Unit]
      After=network-online.target
      Wants=network-online.target
    sudo systemctl enable NetworkManager-wait-online.service

The second command matters: without a service that actually waits for the network, `network-online.target` is reached immediately and the dependency achieves nothing.

**Takeaway:** binding a service to specific addresses creates a dependency on those addresses existing. `Cannot assign requested address` means either the address is not this machine's, or it is not yet. Using `systemctl edit` writes to a drop-in under `/etc/systemd/system/`, leaving the packaged unit untouched — which survives package upgrades, unlike editing the unit directly.

#### Failure 16 — 104 dropped packets that were the router talking to itself

**Symptom:** the `INPUT-DROP` counter reached 119 within minutes of a clean boot, with no test traffic to account for it.

**Investigation:**

    journalctl -k -b | grep INPUT-DROP \
      | grep -oE "PROTO=[A-Z]+ SPT=[0-9]+ DPT=[0-9]+" \
      | sort | uniq -c | sort -rn

        104 PROTO=UDP SPT=5353 DPT=5353
          2 PROTO=TCP SPT=48614 DPT=80
          4 PROTO=UDP SPT=*     DPT=3702

Port 5353 to `224.0.0.251` is mDNS; port 3702 to `239.255.255.250` is WS-Discovery. Source addresses were `10.10.10.1`, `10.10.20.1`, `10.10.30.1` and `10.0.2.15` — every interface of the router. It was announcing itself by multicast on all four segments, and its own firewall was dropping the announcements.

**First attribution, wrong:** assumed `avahi-daemon`, based on the port. It was already inactive. The actual source was `cups-browsed` — "Make remote CUPS printers available locally" — which emits mDNS and WS-Discovery independently of Avahi.

**Fix:** `systemctl disable --now cups-browsed.service cups.service cups.socket cups.path`. Counter stopped advancing immediately.

**Takeaway:** a port number suggests a service; only `ss -tulnp` confirms which process owns it. Attribution by convention is a hypothesis, not a finding.

The wider point: the correct response to unexplained drops was to remove the cause, not to add a rule silencing them. A rule permitting mDNS would have produced a clean log and left the service running. The noise was the signal.

#### Failure 17 — `autoremove` would have deleted the running kernel

**Symptom:** `apt purge --dry-run` listed `linux-image-6.12.94+deb13-amd64` among packages "automatically installed and no longer required".

**Cause:** the kernel had been pulled in as a dependency rather than installed explicitly, so `apt` considered it removable. Running `autoremove` after the purge would have deleted it.

**Fix, before touching anything else:**

    sudo apt-mark manual linux-image-6.12.94+deb13-amd64

**Takeaway:** `--dry-run` exists for this. Reading the simulation before executing is the same discipline as reading `git status` before a commit, and it is what turned an unbootable machine into a two-second correction. `apt-mark manual` is the mechanism for saying "I want this here" about something that arrived as a dependency.

Related, discovered afterwards: the running kernel changed from 6.12.94 to 6.12.101 after the purge and reboot, because GRUB's default selection was regenerated. An unintended kernel change is worth noticing — in production it can alter driver or network behaviour.

---

### Concepts consolidated

#### Chain policy is a safety net, not the mechanism

The `input` chain was built with `policy accept`, populated, tested, and switched to `drop` last. That order matters: creating the chain with `drop` denies everything from the instant it exists, before any allow rule is in place.

Note that the explicit `log ... drop` rule at the end of the chain already blocks everything unmatched, regardless of the policy. The policy catches what falls past the last rule — which, with an explicit drop present, should be nothing. Having both is deliberate: if the final rule is ever deleted, the policy still holds.

#### Logging turns a barrier into a sensor

`policy drop` alone discards silently. The explicit logging rule records source, destination, both interfaces, protocol, ports, TTL and timestamp for every refusal.

That difference produced the most valuable finding of the session. Without logging, `cups-browsed` would still be announcing itself across three segments and nobody would know. The unexplained entries in a log are worth more than the expected ones.

#### Reading a log at volume

Individual entries do not scale. The pattern that does:

    grep PATTERN | grep -oE "FIELDS" | sort | uniq -c | sort -rn

Extract the fields that matter, group, count, order by frequency. It turned 110 unreadable lines into six that told the whole story. This is the first thing to reach for with any volume of log data.

#### Retransmission and scanning look different

Two `INPUT-DROP` entries for port 80 shared `SPT=48614` — the same source port, one second apart. That is TCP retransmitting because nothing answered, not two separate attempts.

A port scan looks different: many SYNs to *different* destination ports, from different source ports. Distinguishing retransmission from reconnaissance is the difference between a useful alert and a false positive.

#### drop and reject are different signals

`nc -zv 10.10.10.1 80` returned `Connection timed out` under the firewall, and `Connection refused` when sshd was down.

`reject` sends a RST — it confirms the host exists and tells a scanner the port is closed. `drop` sends nothing — from outside, a dropped port is indistinguishable from a machine that is switched off. The cost is that legitimate diagnosis is slower too, since a client has to wait out its timer rather than being told immediately.

#### Purging an environment does not purge its ecosystem

Removing GNOME took 9 packages; `autoremove` took 27 more. Both together left 19 services running, of which four still had no business on a router: `ModemManager`, `wpa_supplicant`, `power-profiles-daemon`, `rtkit-daemon`.

Those were not dependencies of the desktop metapackage — they were installed in their own right by the installer's desktop task. Removing the environment does not remove what was installed alongside it, and the remainder has to be handled service by service.

The conclusion for future machines: a router should be installed without a desktop environment in the first place. Most of this session was spent undoing an installation choice made in Lab 01.

#### Defence in depth means layers that fail independently

The firewall already blocked SSH from the external leg. Adding `ListenAddress` was redundant against the current configuration and worth doing anyway: if a rule is later deleted or an exception added without understanding the context, the service still is not listening there.

A control that depends on another control working is not a second layer.

### Outstanding

- [ ] Deploy a host in SERVERS — the segment is empty, so isolation is only testable against a non-existent destination
- [ ] Decide an IPv6 filtering policy, or document its absence as deliberate. `nftables` rules are `table ip` only
- [ ] Review the remaining services (`udisks2`, `low-memory-monitor`, `accounts-daemon`) for necessity
- [ ] Consider `fail2ban` or rate limiting on SSH once the lab is exposed to anything beyond itself
