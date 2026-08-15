# Logbook — Lab 04: Live service and isolation under test

---

## Session 4 — First server, isolation against a live target, bastion access

**Date:** 2026-08-13 (lab) · 2026-08-15 (documentation)
**Duration:** ~4 h
**Module:** 1 — Networking for security

### Objective

Put a real service in the SERVERS segment so that inter-segment isolation can be tested against something that answers, rather than against an address where nothing exists. Establish administrative access to that server without opening a path from the user network, and produce the environment's first genuine log source.

### Steps performed

1. New VM `srv-web` created, Debian 13 netinst, minimal install with the desktop task unselected.
2. Diagnosed and fixed an internal-network name mismatch that left the host on an isolated segment.
3. Completed the installation with the mirror step skipped, then wrote `/etc/apt/sources.list` by hand.
4. `apt upgrade` applied; kernel moved from 6.12.94 to 6.12.101, confirmed with `uname -r` after reboot.
5. nginx installed and verified listening on port 80.
6. `curl` and `openssh-server` installed — neither present in a minimal install.
7. Isolation tested from `ws-user01` against the live service, and the resulting `FWD-DROP` entry read on the router.
8. Administrative access established as `ws-user01 → lab-router → srv-web`, with a key generated on the router.
9. sshd hardened on `srv-web` via `sshd_config.d/hardening.conf`, verified with `sshd -T` and a second session.
10. Snapshot `sesion04-srv-web-ok`.

### Result

SERVERS contains a host that serves. The same address returns `200 OK` locally and times out from USERS, with the refusal logged on the router. Administration reaches the server through the router without any rule permitting USERS to do the same. nginx produces access logs — the first log source in the environment worth centralising.

---

### Failures and diagnosis

#### Failure 18 — Internal network named `intnet` instead of `intnet-servers`

**Symptom:** after installation, the gateway did not answer.

    $ ping -c2 10.10.20.1
    From 10.10.20.50 icmp_seq=1 Destination Host Unreachable
    From 10.10.20.50 icmp_seq=2 Destination Host Unreachable

**Diagnosis:** the message is emitted by *the machine itself* — `From 10.10.20.50`, the host's own address — not by the router. That is the signature of an unanswered ARP request: the host broadcasts "who has 10.10.20.1?" and nobody replies. Address and route were both correct inside Debian, so the failure was at layer 2. VirtualBox showed the adapter attached to an internal network named `intnet`.

**Cause:** VirtualBox internal networks are identified purely by name. `intnet` and `intnet-servers` are two separate, mutually invisible networks — `srv-web` was alone on a segment with no router in it. The router's `enp0s9` leg has been on `intnet-servers` since Lab 01.

**Fix:** power the VM off — the change is not reliable while running — set Adapter 1's name to `intnet-servers` exactly, and boot.

    64 bytes from 10.10.20.1: icmp_seq=1 ttl=64 time=0.42 ms
    64 bytes from 8.8.8.8:    icmp_seq=1 ttl=62 time=28.1 ms

The two TTL values are the evidence: 64 for the gateway, which replied directly with no hop consumed, and 62 for the internet, two hops away through the router and VirtualBox's NAT engine — the value established in Lab 02.

**Takeaway:** the same class of failure as the orphaned NetworkManager profile in Failure 10 — a name that does not match exactly creates a separate entity rather than an error. Nothing warns you; you get silence and an unanswered ARP. The wider result is worth noting too: a host that had never existed before gained internet access without touching the router, so the NAT and forwarding built in Lab 02 work for anything appearing in an internal segment, not only for the machine they were tested against.

#### Failure 19 — `curl` not installed on a minimal Debian install

**Symptom:** while verifying nginx was serving, `curl -I http://localhost` returned `command not found`.

**Cause:** the netinst minimal profile does not include it.

**Fix:** `apt install -y curl`. `wget -q --spider URL` is the already-present alternative when installing is inconvenient.

**Takeaway:** minimal means minimal. Tools assumed present on a desktop install are absent, which is the intended trade — every package not installed is surface not exposed.

#### Failure 20 — openssh-server not installed either

**Symptom:** before hardening SSH, a check revealed sshd was not installed at all. Administration to that point had relied on the VirtualBox console.

**Fix:** `apt install -y openssh-server`, then proceed to hardening.

**Takeaway:** the same gap as Failure 19, and a more consequential one — "minimal" does not include a service as fundamental as SSH. It has to be added deliberately, which is the point of a minimal base rather than a defect of it. The identical gap recurred on `mgmt-01` in Lab 05.

#### Failure 21 — The isolation test run from the wrong machine

**Symptom:** the first `curl -I http://10.10.20.50` succeeded, briefly appearing to contradict the isolation policy.

**Diagnosis:** the prompt read `vboxuser@srv-web`. A host requesting its own network address is local traffic — it never crosses the router and never meets the `forward` chain, functionally identical to `localhost` by a different address.

**Fix:** re-run from `ws-user01`, verifying with `hostname` first. The contrast is the whole point of the lab:

    vboxuser@srv-web:~$   curl -I http://10.10.20.50
    HTTP/1.1 200 OK

    vboxuser@ws-user01:~$ curl -I --connect-timeout 3 http://10.10.20.50
    curl: (28) Failed to connect to 10.10.20.50 port 80 after 3011 ms

Exit code 28 is curl's timeout, useful in scripts for distinguishing a connection failure from other errors.

**Takeaway:** with three near-identical VMs on screen, `hostname` before each test stopped being advice and became procedure. This is the context-drift failure first recorded as Failure 8, and it recurred again throughout Lab 05.

#### Failure 22 — `ssh-copy-id` on the router: `No identities found`

**Symptom:** attempting to install a key from the router onto `srv-web` failed.

    vboxuser@lab-router:~$ ssh-copy-id vboxuser@10.10.20.50
    /usr/bin/ssh-copy-id: ERROR: No identities found

**Cause:** across three labs the router had always been an SSH *destination*, never an origin. The keys handled so far belonged to Windows, macOS and `ws-user01`; the router had none of its own to offer.

**Fix:** generate one, then copy it.

    ssh-keygen -t ed25519 -C "lab-router-to-srv-web"
      SHA256:hLw8wneQySm4FgTAiotdBN37osE015RcsFZtD6a3hIQ

**Correction, recorded 2026-08-15:** this entry originally stated the key was generated with an empty passphrase, and gave the fingerprint as `hLu8une...`. Both were wrong. SSH prompts for a passphrase when the key is used, and the private key file is 464 bytes — an unencrypted Ed25519 key is around 399, so the file is encrypted. The fingerprint above is the value read from the router itself; the earlier one was a transcription error made while writing this logbook.

**Consequence, discovered later:** the passphrase was not recorded anywhere and is not remembered. `ssh-keygen -y -f ~/.ssh/id_ed25519` returns `incorrect passphrase supplied to decrypt private key`. The key is therefore a valid authorised credential on `srv-web` that nobody can use — the private half is intact but permanently locked. That is an audit finding in its own right: authorised access with no operational owner. It is tracked in the Lab 05 outstanding items, where the replacement key from `mgmt-01` has already been installed alongside it.

**Takeaway:** the router changing role from server to client is not a detail — it is the moment it becomes an administration point, and it is exactly the property Lab 05 then argues against. An administrative private key living on the routing device is the concrete form of the risk.

A second takeaway arrived only when the key was needed again: a passphrase that is not written down at the moment of creation is a passphrase that will be lost. Two days was enough. Generating a credential and recording nothing about it produces exactly this outcome — the access remains authorised while becoming unusable, which is the worst of both properties.

#### Failure 23 — `Bad archive mirror`: a content error that proved the network worked

**Symptom:** the Debian installer failed at the mirror step, on a host whose segment had just been misconfigured (Failure 18). The obvious reading was a second network fault.

**Diagnosis:** dropping to a shell inside the installer with `Alt+F2` allowed the layered sequence to run before the system existed:

    ip addr              → 10.10.20.50/24 present
    ip route             → default via 10.10.20.1
    ping -c2 10.10.20.1  → replies
    ping -c2 8.8.8.8     → replies, ttl=62
    ping -c2 deb.debian.org → resolves and replies

Every layer worked. The installer log then gave the real answer:

    choose-mirror: DEBUG: command: wget ... http://deb.debian.org/debian/dists/trixie/Release
    choose-mirror: WARNING **: mirror does not support the specified release (trixie)

The `wget` **succeeded**. What failed was the content: the mirror no longer served `trixie` at the expected path. The ISO identified itself as `Debian GNU/Linux 13.6.0 _Trixie_ ... 20260711` — a July build, run in August, across a repository reorganisation.

**Fix:** skip the mirror step, complete the install from the netinst base, then repair `sources.list` on the booted system (Failure 24).

**Takeaway:** read the error for what it says, not for what the surrounding context suggests it should say. Failing at a late stage is evidence that every earlier stage succeeded — and that inference paid off twice, because when the same message appeared on `mgmt-01` in Lab 05, it ruled out a repeat of Failure 18 before the install had finished.

#### Failure 24 — `sources.list` contained only the CD-ROM entry

**Symptom:** nginx could not be installed after the system booted.

**Diagnosis:** the file held a single entry.

    $ cat /etc/apt/sources.list
    deb cdrom:[Debian GNU/Linux 13.6.0 _Trixie_ - Official amd64 NETINST]/ trixie main

Skipping the mirror step in Failure 23 meant the installer never wrote the network repositories, so `apt` could only offer what was physically on the ISO.

**Fix:** replace the file with the official network repositories, then `apt update` and install.

**Takeaway:** a workaround has consequences downstream. Skipping the mirror was the right call to get the system installed, but it silently left the package manager with no source of packages — a state that surfaces only when something needs installing.

---

### Concepts consolidated

#### Blocking a live service is a stronger proof than blocking a dead address

For three labs the isolation policy was tested against destinations that did not exist, where a drop and an absence are indistinguishable from the client. With nginx answering `200 OK` locally and timing out from USERS, the difference is demonstrated rather than assumed.

This is why the empty SERVERS segment was tracked as an outstanding item in Lab 03 rather than ignored. A policy that has only ever been tested against nothing has not been tested.

#### `output` is a third path, distinct from `input` and `forward`

Traffic *originating* on the router reaches any segment without traversing `forward`, so the router could administer `srv-web` with no rule change while USERS could not reach it at all.

That property made the bastion jump possible without weakening anything. It is also a reminder that a default-deny `forward` policy says nothing about what the router itself can initiate — a distinction that matters if the router is ever compromised.

#### VirtualBox internal networks are joined by name, and the network is the switch

Two machines both "on an internal network" are not connected unless the name matches character for character. There is no warning for a mismatch, only silence.

The related confusion is what the name refers to. `intnet-servers` is the switch — what connects machines to each other. `10.10.20.1` is an address belonging to the router that happens to sit on that switch. Conflating them makes the diagnosis harder than it needs to be, because the host had the correct gateway address configured and still could not reach it.

#### Two configurations in two places

The address and gateway are set inside Debian; which network the adapter is attached to is set in the hypervisor. Both were correct in isolation during Failure 18 — the card was correctly configured and plugged into the wrong socket.

Diagnosis has to check both layers. Neither one alone reveals the problem, and a fault in one cannot be fixed in the other.

#### Layered diagnosis works even without a booted system

`Alt+F2` opens a shell inside the Debian installer, enough to run own address → route → gateway → internet by IP → name resolution. The first step that fails localises the break.

Having that sequence available before the operating system exists turned an ambiguous installer error into a precise diagnosis, and it is the same ordering used on every network fault in the project so far.

#### A content error is evidence of a working connection

The mirror failure reported that `trixie` was unavailable — which required successfully reaching the mirror to discover. Failing late proves everything earlier succeeded.

The inference was reused directly in Lab 05: the same message on `mgmt-01` meant its segment name had to be correct, because the installer got far enough to complain about release names rather than about connectivity.

#### A blocked attack leaves its trace on a different host than a successful one

The `ws-user01 → srv-web` attempt appears only in the router's `FWD-DROP` log, never in nginx's access log, because it never reached nginx. The successful local requests appear only in nginx.

Neither log alone tells the whole story. This is the case for centralising logs from every layer, and the reason a SOC correlates sources rather than reading them in isolation.

#### Tools announce themselves

The `curl/8.14.1` user-agent is a default signature; `sqlmap`, `nikto` and `nmap` do the same unless deliberately masked. A first, cheap detection rule reads the user-agent field.

That it can be forged is the next lesson rather than a reason to skip the first. The reciprocal is also true: nginx's own `Server`, `ETag` and `Last-Modified` headers are reconnaissance an attacker collects about this server.

#### Privilege separation by process design

nginx runs a root-owned master that binds port 80 and unprivileged workers that serve requests. A worker compromised while handling a malicious request holds no root.

The privilege drop is structural rather than configured, and the pattern recurs across well-designed daemons. Worth recognising as a defensive property rather than an implementation detail.

#### A frozen ISO ships a stale kernel

The July build ran 6.12.94; `apt upgrade` brought 6.12.101 once network repositories existed. `uname -r` reports the *running* kernel, which changes only after a reboot — installing a new kernel and running it are two separate events.

This is the same kernel that, one lab earlier, had to be marked manual before a purge. Version churn is a standing feature of building from a point-in-time image.

#### A correct pattern can still contain a shortcut

The bastion jump is the right model. Putting it on the router is not, because it collapses two functions production separates and places an administrative private key on the routing device.

Recording the compromise — rather than presenting the lab as production practice — is what makes the progression to Lab 05 legible. A laboratory that documents where it cuts corners demonstrates more judgement than one that pretends it does not.

### Outstanding

- [ ] Collect evidence from `srv-web` and `lab-router` — the capture commands were run but the files were never extracted, and `srv-web` has no shared folder, so they have to exit via the router to `/media/sf_shared` before the usual SMB mount on the Mac
- [ ] Suppress nginx version headers (`server_tokens off`) as a hardening item
- [ ] Separate the bastion from the router — addressed in [`lab-05-mgmt-bastion`](../lab-05-mgmt-bastion/)
- [ ] Decide an IPv6 filtering policy, or document its absence as deliberate. Carried from Lab 03; `nftables` rules remain `table ip` only
- [ ] Add a note to the Lab 03 README recording that the empty SERVERS segment described there was addressed here
