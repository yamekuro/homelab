# Logbook — Lab 05: Management segment and bastion

---

## Session 5 — Management segment, bastion host, and removing the router shortcut

**Date:** 2026-08-13 → 2026-08-15
**Duration:** ~1 d
**Module:** 1 — Networking for security

### Objective

Replace the router-as-bastion shortcut left by Lab 04 with a dedicated management segment and a purpose-built jump host. Establish an encrypted administrative path from the laptop that does not give the bastion a second unfiltered route to the internet, then remove the router's role as a session endpoint in every layer that grants it. Record what happens on the bastion, and test whether that recording can be trusted.

### Steps performed

1. Fifth router leg added from the host CLI — the GUI exposes only four adapters — and configured with a `seg-mgmt` profile on `10.10.99.1`.
2. `mgmt-01` installed at `10.10.99.10`; firewall rules written for `enp0s16`, restricting egress to 53, 80 and 443.
3. OpenSSH installed and verified listening before anything else was touched.
4. GNOME purged after reading the simulation in full and protecting `sudo`, `network-manager` and the kernel.
5. Administrative key generated on `mgmt-01` and distributed to the router; `~/.ssh/config` written with `AddKeysToAgent`.
6. External access built: `natpf1` rule on the Windows host, DNAT and forward rules on the router, ProxyJump configured on macOS.
7. Router removed as a bastion in three layers — credential, `ListenAddress`, `input` chain — after the new path was verified end to end.
8. Session recording installed via `/etc/profile.d`, then attacked to establish its limits.
9. Ruleset persisted to `/etc/nftables.conf`. Snapshots `sesion04-post-purga-gnome` and `lab04-completo`.

### Result

Administration originates from a dedicated segment and passes through a single controlled host. The router listens on one address, holds no credential from the user network, and drops SSH from the other three segments at the firewall. `mgmt-01` is single-homed, carries no desktop, and reaches the internet only on three ports. Session recording works and is demonstrably not tamper-resistant, which is the finding rather than a defect.

---

### Failures and diagnosis

#### Failure 25 — The VirtualBox GUI exposes only four network adapters

**Symptom:** the router already had four legs — NAT uplink plus USERS, SERVERS and DMZ — and Settings → Network offered no fifth tab for the management segment.

**Cause:** the limit is in the graphical interface, not the hypervisor.

**Fix:**

    VBoxManage modifyvm lab-router --nic5 intnet --intnet5 "intnet-mgmt"

**Takeaway:** a capability absent from an interface is not necessarily absent from the product. Hitting the edge of a graphical tool is a prompt to drop to its command line rather than to redesign around the constraint — worth remembering as the lab grows past what the GUI was built to show.

#### Failure 26 — GNOME installed despite selecting a minimal install

**Symptom:** `mgmt-01` was intended as a minimal system and booted into a full desktop.

**Cause:** the Debian installer's software selection screen has the desktop environment **checked by default**. Leaving the defaults means accepting GNOME.

**Consequence:** a management bastion — the host whose entire purpose is to be a small, controlled entry point — shipped with the largest attack surface in the environment. Purging it became the opening task of the next day: 159 packages, roughly 10% of the total, including `xserver-xorg-legacy`, described by `dpkg` as a *setuid root Xorg server wrapper*. A binary any local user can execute with root privileges, on a machine with no monitor.

**Takeaway:** "minimal" is a choice made at one specific screen, not a property of the netinst ISO. The same trap caught `lab-router` in Lab 01 and cost most of Lab 03 to undo; it was avoided on `srv-web` in Lab 04; it caught the next machine anyway. Recurrence despite knowing about it is the useful part of the record.

#### Failure 27 — `debootstrap` failed on a dirty disk

**Symptom:** a reinstall over an existing installation failed during base system extraction.

    tar: file exists

**Cause:** `debootstrap` unpacks onto a filesystem it expects to be empty. Residue from the previous install collided with files it was writing.

**Fix:** reinstall using guided partitioning, so the disk is repartitioned and formatted rather than reused.

**Takeaway:** an installer error can be about the state of the target rather than the operation attempted. Reusing a disk without wiping it is a false economy.

#### Failure 28 — DNS blocked during installation by the router's own firewall

**Symptom:** the `mgmt-01` installer could not fetch packages.

    wget: unable to resolve host address 'deb.debian.org'

**Diagnosis:** the reflex was to suspect the internal network name, the Lab 04 pattern, or the mirror, which had already failed once on `srv-web`. Neither. The `enp0s16` leg existed and carried traffic, but the router's firewall had **no rules for it at all**. With `forward` at default-deny, management DNS queries were dropped in silence.

**Fix:** write forward rules for `enp0s16` — DNS on 53, plus HTTP and HTTPS on 80 and 443. That is also the deliberate egress restriction for the bastion rather than a temporary workaround, so the fix and the design decision are the same change.

**Takeaway:** this is default-deny working exactly as designed. Bringing a new segment into existence granted it nothing; every path it needed had to be stated explicitly, and until each was, traffic disappeared without a message. A permissive default would have made the segment work immediately and taught nothing.

#### Failure 29 — nft rules added *after* the drop, in two separate chains

The lab's most instructive failure, because it happened twice and the second occurrence came after the first had already been diagnosed.

**Symptom, both times:** a newly added rule appeared correctly in `nft list ruleset` and had no effect whatsoever.

**Diagnosis:** `nft add rule` appends to the **end** of a chain. Both chains terminate with an explicit logging drop that has no match criteria:

    counter packets 104 bytes 7904 log prefix "FWD-DROP: " drop

Nothing passes beyond it, so a rule appended afterwards sits in dead ground — syntactically valid, visible in the listing, never evaluated. The first occurrence was the rule permitting SSH from the management segment, in `input`. The second was the rule permitting DNAT'd traffic through to `10.10.99.10:22`, in `forward`:

    iifname "enp0s16" oifname "enp0s3" udp dport 53 counter accept
    counter packets 104 bytes 7904 log prefix "FWD-DROP: " drop
    iifname "enp0s3" oifname "enp0s16" ip daddr 10.10.99.10 tcp dport 22 accept   ← never reached

**Fix:** delete the misplaced rule and position the replacement explicitly, using handles from `nft -a list chain`:

    nft delete rule ip lab-filter forward handle 19
    nft insert rule ip lab-filter forward position 9 <rule>

Note the asymmetry: `insert ... position N` places the rule *before* handle N, while `add ... position N` places it *after*.

**Takeaway:** in an ordered ruleset, existence and effect are different properties. Confirming that a rule appears in the output confirms nothing about whether it runs. The check is its position relative to the terminating rule, or better still its packet counter under live traffic. This is the same class of error as the false "OK" results in Failure 36, arriving from a completely different direction — something looked configured and was inert.

#### Failure 30 — sshd reported `inactive`, but the package was never installed

**Symptom:** `systemctl is-active ssh` returned `inactive` on the fresh `mgmt-01`.

**Diagnosis:** the initial hypothesis was Debian 13's socket activation, under which `ssh.service` is permanently `inactive` while `ssh.socket` listens. A real behaviour, and worth ruling out — but the wrong explanation here.

    dpkg -l openssh-server   → un  (unknown, never installed)
    systemctl is-enabled ssh.service ssh.socket → not-found / not-found
    ss -lnt | grep ':22'     → nothing

**Consequence:** installing OpenSSH became step 0, mandatory before purging GNOME. Purging first would have left the machine with neither a desktop nor SSH, reachable only through the VirtualBox console — the exact gap this lab exists to close.

**Takeaway:** `inactive` is not `absent`. Two different states with two different fixes, disambiguated by `dpkg` state and a listening-socket check. The same minimal-install gap as `srv-web` in Failure 20, arriving on the machine where it mattered most.

#### Failure 31 — The initial SSH test ran against the wrong machine

**Symptom:** the first end-to-end test was issued from `mgmt-01` targeting `10.10.99.10` — `mgmt-01`'s own address — and then failed with `Host key verification failed`.

**Diagnosis:** two errors stacked. The kernel delivers traffic addressed to a local address internally, so the packet never left `enp0s3` and the test proved nothing about network reachability. And the host-key prompt received a bare Enter, which aborts it; the question requires the full word `yes`.

**Fix:** run the test from `lab-router` — same segment, genuinely separate host — and answer `yes` after comparing the fingerprint out of band:

    mgmt-01$    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
    lab-router$ ssh vboxuser@10.10.99.10
      ED25519 key fingerprint is SHA256:1crjOx2i3W1VpmDhuOzGvILfTsAiSKWAmEjSDn9qPV4

**Takeaway:** an SSH test that loops back to its origin verifies nothing. Comparing the fingerprint against the server's own key file, rather than accepting it blind, is the difference between establishing trust and assuming it. Third recurrence of the context-drift failure first recorded as Failure 8 — the window title read `lab-router` while the prompt read `mgmt-01`.

#### Failure 32 — `ssh-copy-id` blocked by a key-only router

**Symptom:**

    /usr/bin/ssh-copy-id: ERROR: ... Permission denied (publickey).

**Diagnosis:** the parenthesis lists the methods the server offered. Only `publickey` — the router had been hardened in Lab 03 and no longer accepts passwords. `ssh-copy-id` therefore needed a key to log in and install the key that was not yet installed: a circular lockout.

**Fix:** reverse the direction. The router can reach `mgmt-01`, which still accepted passwords, so pull rather than push:

    lab-router$ cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak
    lab-router$ ssh vboxuser@10.10.99.10 'cat ~/.ssh/id_ed25519_admin.pub' >> ~/.ssh/authorized_keys

**Takeaway:** key distribution does not have to move in the direction of the intended session. Whichever host currently accepts a login is the one that runs the copy — and pulling avoids transcribing eighty characters by hand, which was the alternative.

#### Failure 33 — SSH refused on the router's own management address

**Symptom:** from `mgmt-01`, connecting to `10.10.99.1` returned `Connection refused`.

**Diagnosis:** refused is a RST, meaning the packet reached the router and was actively rejected — not dropped, which would have produced a timeout. That distinction placed the fault on the service rather than the filter, exactly as in Failure 15. The firewall counter confirmed it, showing the SYNs *accepted*:

    iifname "enp0s16" tcp dport 22 counter packets 2 bytes 120 accept

    ss -lnt on the router:
      LISTEN  10.10.10.1:22
      LISTEN  10.10.20.1:22
      LISTEN  10.10.30.1:22

**Cause:** the explicit `ListenAddress` directives added in Lab 03 had never been extended to the new leg.

**Fix:** add `ListenAddress 10.10.99.1`, validate with `sshd -t`, restart.

**Takeaway:** the finding is more interesting than the fix. Before the change, the router accepted SSH from USERS, SERVERS and **DMZ**, but not from the management segment — administration open from the most exposed network and closed from the one built to administer it. Backwards, and recorded as a finding rather than as the starting state.

#### Failure 34 — The live snapshot appeared to hang at 90%

**Symptom:** `VBoxManage snapshot ... --live` on `mgmt-01` sat at 90% far longer than the 2048 MB of RAM suggested it should.

**Diagnosis:** not hung. The final phase dumps guest memory to disk, and the state confirmed work in progress:

    VMState="livesnapshotting"

The `.sav` file showed 0 bytes throughout. That was a false indicator, not a symptom — an NTFS directory entry is not updated while the file is held open for writing. Using file size to gauge progress was my suggestion and it was wrong.

**Fix:** watch `VMState`, which is the reliable signal. It returned to `running` on its own; when it is unclear whether a live snapshot completed or was cancelled, `snapshot list` disambiguates.

**Takeaway:** for a snapshot taken only as a pre-change restore point, `--live` was the wrong tool. Powering the VM off and taking it cold skips the memory dump entirely and finishes in seconds. Adopted for the rest of the lab, and the reason the two snapshots that matter here were taken cold.

#### Failure 35 — `apt purge` would have removed `sudo` with root locked

**Symptom:** the simulated GNOME purge, read in full, listed `sudo*` among the packages `--auto-remove` would take.

**Diagnosis:** `sudo` was marked automatic and nothing depended on it, so the cleanup swept it as an orphan — not as a dependency of the desktop. The severity came from the account state:

    $ sudo passwd -S root
    root L 2026-08-13 0 99999 7 -1

`L` is locked, the Debian default when the installer is given an empty root password. Purging `sudo` would have left **no privilege-escalation path at all** — not `sudo`, not `su`, not root login. Recovery would have meant rescue mode or restoring the snapshot.

**Fix:** `apt-mark manual sudo` before purging. The same protection was applied to `network-manager`, without which the VM would have returned from the reboot with no address.

**Takeaway:** `--auto-remove` removes anything currently orphaned, not only dependencies of the named package. The same lesson as Failure 17, where the running kernel needed identical protection. The snapshot was the safety net — but what actually prevented the incident was reading the simulation, because the filter meant to catch this said OK. See Failure 36.

#### Failure 36 — Three "OK" results that verified nothing

Three instances of one failure mode, grouped because the lesson is single.

**First:** the critical-package filter returned nothing and a `|| echo OK` construct printed a reassuring message.

    grep -c '^Remv' /tmp/purga-sim.txt          → 0
    grep -E '^Remv (sudo|systemd|...)' ... || echo "OK: ningun paquete critico"
                                                → OK: ningun paquete critico

apt 3.0 in Trixie no longer emits `Remv` lines. It uses a `The following packages will be REMOVED:` block with space-separated, asterisk-marked names. The pattern matched nothing because the format had changed, not because nothing would be removed — and `sudo*` was in that block, as Failure 35 records.

**Second:** a long simulation command wrapped mid-line while being typed by hand, so bash split it. The first part ran and printed to screen; the second was executed as a bare command and failed, and that error — captured by `2>&1` — became the file's only content:

    -bash: gdm3: command not found

The subsequent filter found no critical packages because the file held an error message rather than a simulation.

**Third:** a reused filename carried a typo, `sims3.txt` for `sim3.txt`, and `wc` reported `No such file`. This was the harmless member of the family: a loud, unambiguous error rather than a false success.

**Fix:** validate that the file holds real content *before* filtering it, then run a positive control:

    wc -l /tmp/sim3.txt                          → 204
    grep -c 'will be REMOVED' /tmp/sim3.txt      → 1
    tr ' ' '\n' < /tmp/sim3.txt | tr -d '*' | grep -xE 'gdm3|gnome-core|xserver-xorg'
                                                 → gdm3, gnome-core, xserver-xorg

With the pipeline proven to produce output when output exists, a subsequent empty result for critical packages means "none present" rather than "filter broken".

**Takeaway:** `|| echo OK` reports OK whenever its left side finds nothing, which is not the same as nothing being wrong. This is the logbook's central point, and the direct reason positive controls matter in detection engineering: a rule that does not fire because its parser no longer matches the log format looks identical to a rule that does not fire because there is no attack.

#### Failure 37 — Append-only did not protect log contents, and the test that "passed" never ran

**Symptom:** the tamper test appeared to confirm the protection.

    $ rm /var/log/session-logs/*.log
    rm: cannot remove '/var/log/session-logs/*.log': No such file or directory

**Diagnosis:** that is not the protection speaking. The `1733` directory permission denies *read*, so the shell could not expand the glob; it passed the literal string to `rm`, which found no file by that name. The control was never exercised. Re-run with an explicit filename it behaved correctly:

    $ rm /var/log/session-logs/vboxuser-20260814-121102-1467.log
    rm: cannot remove '...': Operation not permitted

**The real gap:** `chattr +a` on a *directory* prevents deleting or renaming entries. It says nothing about the contents of files inside it, and I had wrongly stated that newly created files would inherit the restriction. Each log is owned by the session user with write permission, because that is how `script` creates it:

    $ wc -c ...-1467.log      → 14040
    $ : > ...-1467.log
    $ wc -c ...-1467.log      → 0

Fourteen kilobytes of an in-progress recording, erased without root, with the attribute set.

**Takeaway:** host-local session logging is not tamper-resistant against a user holding privileges on that host, and cannot be made so by local means. Ship events off-host in real time — the job of the Wazuh agent in Lab 06. And once again, a check that appeared to pass had verified nothing: the glob failure and the false OK of Failure 36 are the same error wearing different clothes.

---

### Concepts consolidated

#### Default-deny applies to new segments too

Creating `intnet-mgmt` and giving the router a leg on it granted exactly nothing. Every path the segment needed — DNS, HTTP and HTTPS for updates, SSH inbound — had to be stated explicitly, and until each was, traffic died in silence.

A permissive default would have made the segment work immediately and demonstrated nothing. The installer failing to resolve a hostname was the policy behaving correctly, not a fault to route around.

#### Existence in a ruleset is not evaluation

A rule appended after a terminating drop is visible, syntactically valid, and inert. Position relative to the catch-all is the property that matters, and a packet counter under real traffic is the only proof it runs.

Recorded twice in this lab, in two chains, the second time after the first had been diagnosed. Knowing about a failure mode is not the same as having internalised it.

#### Not answering a ping is not the absence of connectivity

`mgmt-01` resolves DNS and downloads over HTTP while failing every ICMP echo, because the egress policy permits 53, 80 and 443 and nothing else.

Reachability is per-protocol and per-port, not a single boolean. Reaching for `ping` as a first test on a filtered host produces a confident wrong answer, which is worse than no answer.

#### Link is not reachability; a configured route is not a functional one

`mgmt-01` shows `enp0s3` UP with its address and a default route to `10.10.99.1` whether or not the router is powered on — a VirtualBox internal network keeps the link up regardless of who else is on the segment. Nothing on the host betrays a dead gateway.

`ip route show` states intent. Only generating traffic and seeing it return verifies fact. The distinction matters in a SOC, where an interface reported as healthy is routinely used to dismiss a correct hypothesis.

#### Two independent SSH authentications, in opposite directions

The client proves itself to the server through `authorized_keys`: the server sends a random challenge, the client signs it with its private key, the server verifies the signature against the stored public key. The private key never crosses the network.

The server proves itself to the client through `known_hosts`, using its own host key. The two are separate exchanges, and confusing them makes the prompts unreadable. `Enter passphrase for key` means the server accepted the key and only local decryption remains; an account-password prompt means the key was refused and SSH fell back.

#### The public key is derived from the private key, not a copy of it

The relation runs one way, which is the entire basis of asymmetric cryptography: the public key can be published without weakening anything. `authorized_keys` is a plain list of authorised public keys, and nothing in it is signed or encrypted.

Distribution direction is therefore irrelevant. SSH pull, USB, or typing it by hand all work, because the only thing that matters is the correct file arriving on the correct host.

#### ProxyJump transports bytes, not credentials

The jump host opens a TCP tunnel and the second SSH session authenticates end to end through it. `mgmt-01` never decrypts the laptop-to-router session and never sees the passphrase, which is why the laptop's private key never needs to touch the bastion.

The trade-off is that a pure ProxyJump leaves nothing to record on the jump host — only connection metadata in `sshd`'s log. That is precisely the gap session recording exists to fill, and it is why the two mechanisms coexist rather than one replacing the other.

#### Removing a bastion means closing three independent layers

Credential, service and firewall: `authorized_keys`, `ListenAddress`, and the `input` rule. Each is closed separately because each fails separately.

A control that depends on another control working is not a second layer — the same point Lab 03 made about binding sshd to internal addresses when the firewall already blocked the external leg.

#### Open the new path, verify it, then close the old one

The ordering principle running through the whole lab. The DNAT path was proven end to end before the router's `ListenAddress` and `authorized_keys` were touched.

Closing first would have meant recovery only through the VirtualBox console — which is exactly the dependency the management segment exists to remove, so removing the shortcut before the replacement worked would have been theatre.

#### A hypervisor GUI is a subset of the hypervisor

Four adapter tabs is an interface limit, not a product limit. Hitting the edge of a graphical tool is a prompt to drop to its API rather than to redesign around the constraint.

#### Positive control: prove the check can fail

Before trusting a silent result, generate the event that must trip it. Used here to validate the purge filter — grep for packages that *must* appear and confirm they do — and the append-only attribute, deleted by explicit name to confirm `Operation not permitted`.

This is the same discipline that validates a detection rule: fire the technique, confirm the alert. A rule that has never fired is not evidence of safety, and the four false results in this lab are the argument in miniature.

#### Reduced surface is not always visible in `ss`

Purging GNOME removed 159 packages and 700 MiB of resident memory, and changed the listening-socket count not at all. A desktop communicates over Unix sockets and D-Bus, both local to the filesystem and invisible to `ss -lnt`.

The real reduction was elsewhere: `xserver-xorg-legacy`, a setuid root wrapper any local user could execute, on a machine with no monitor. Choosing the wrong metric would have shown no improvement and hidden a genuine privilege-escalation path being closed.

#### Host-local audit is not tamper-resistant

A log stored on the machine where the audited user holds privileges can be truncated in one command. Directory-level `chattr +a` prevents deletion and renaming while leaving file contents writable, and the file is owned by the user being recorded.

Real audit ships events off-host in real time, to a collector the audited user cannot write to. Every local hardening measure raises the cost of tampering; none of them closes it.

### Outstanding

- [ ] Collect evidence from `mgmt-01` and `lab-router` — ruleset with rule order, `sshd -T`, key fingerprints, the `/etc/profile.d` trigger, and a truncated session log
- [ ] **Reboot the router and verify the persisted ruleset holds** — `nftables.conf` was written and the service is `enabled`, but the machine has not been restarted since, so persistence is configured and unproven
- [ ] **Revoke `lab-router-to-srv-web` from `srv-web`** — the router was removed as a bastion inbound but retains its own administrative key outbound, which is the Lab 04 shortcut only half undone
- [ ] Forward rules MGMT → USERS/SERVERS/DMZ, one direction only, and distribute the admin key to `ws-user01` and `srv-web` — the management segment cannot yet reach anything it is meant to manage
- [ ] Rename the `Wired connection 1` NM profile on `mgmt-01` to match the `seg-mgmt` convention used on the router
- [ ] Decide an IPv6 filtering policy, or document its absence as deliberate. Carried from Lab 03; `nftables` rules remain `table ip` only
