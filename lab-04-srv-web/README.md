# Lab 04 — Live service and isolation under test

Continuation of [`lab-03-hardening`](../lab-03-hardening/). That lab closed the router's own attack surface but left one item open: the SERVERS segment was empty, so inter-segment isolation could only be tested against a destination that did not exist. A dropped packet to a dead address and a dropped packet to a live service look identical from the client.

This lab deploys `srv-web` — Debian 13 minimal running nginx at `10.10.20.50` — and tests the policy against it. The same server answers or does not depending on where the request comes from, which is the property the lab has been building toward for three modules. It also establishes SSH administration without opening a hole in the isolation, using the router as a jump host.

Lab 03 closed with the instruction to install this machine without a desktop environment. That instruction was followed, and it is the only installation choice in the project so far that did not have to be undone later.

## What it demonstrates

| Capability | Mechanism |
|---|---|
| A real service exists in SERVERS | nginx on `srv-web`, `10.10.20.50:80` |
| Isolation holds against a live target | `curl` from USERS times out; `FWD-DROP` logged on the router |
| The segment still has egress | `ping 8.8.8.8` returns `ttl=62` through NAT |
| Administration without opening USERS → SERVERS | Bastion jump via the router |
| Key-only SSH on the server | `sshd_config.d/hardening.conf` |
| The lab produces a log source | `/var/log/nginx/access.log` |

## Building the host

Two obstacles preceded any of the security work, and each produced a diagnostic worth keeping.

The VM's adapter was attached to an internal network named `intnet` rather than `intnet-servers`. VirtualBox identifies internal networks purely by name, so the server sat alone on a segment with no router in it. The symptom was an unanswered ARP:

    From 10.10.20.50 icmp_seq=1 Destination Host Unreachable

The message is emitted by the machine itself, not by the router — the signature of a host that broadcast "who has 10.10.20.1?" and received no reply. Address and route inside Debian were both correct. The fault was one layer down.

The installer then failed at the mirror step, and the reflex reading was a second network fault. The installer's own log said otherwise:

    choose-mirror: DEBUG: command: wget ... http://deb.debian.org/debian/dists/trixie/Release
    choose-mirror: WARNING **: mirror does not support the specified release (trixie)

The `wget` succeeded. The host resolved DNS, crossed the router under NAT, and fetched — what failed was the content. The ISO identified itself as `Debian GNU/Linux 13.6.0 _Trixie_ ... 20260711`, a July build run in August across a repository reorganisation. Reaching a content error at all proves the network path works end to end.

The install completed from the netinst base with the mirror skipped, which left `/etc/apt/sources.list` holding only a `deb cdrom:` entry and no way to install nginx until the network repositories were written by hand. With those in place, `apt upgrade` moved the kernel from the ISO's frozen `6.12.94` to `6.12.101` — the same version transition the router underwent in Lab 03, arriving here by a different route.

nginx installed as exactly two packages, `nginx` and `nginx-common`. It binds `0.0.0.0:80` and `[::]:80` — the same all-interfaces, IPv4-and-IPv6 surface seen on sshd before Lab 03 restricted it — and runs as two processes:

    root  845  nginx: master process
    nginx 848  nginx: worker process

The master binds the privileged port as root; the worker serves requests without privilege. A worker compromised while handling a malicious request holds no root. The privilege drop is structural rather than configured.

## The isolation test

Two requests to the same address, from two places:

    # from srv-web itself
    curl -I http://localhost                        → HTTP/1.1 200 OK

    # from ws-user01, crossing the router
    curl -I --connect-timeout 3 http://10.10.20.50  → curl (28) Connection timed out

And on the router, the reason:

    FWD-DROP: IN=enp0s8 OUT=enp0s9 SRC=10.10.10.10 DST=10.10.20.50 PROTO=TCP DPT=80 SYN

Every field carries part of the story. `IN=enp0s8 OUT=enp0s9` — entered from USERS, attempting to leave toward SERVERS, both interfaces internal, so this is `forward` traffic and `OUT=` is populated exactly as Lab 03 established. `DPT=80` is a service port rather than an ICMP probe. `SYN` is the first packet of the handshake, cut before it could complete.

Three log entries shared the same `SPT`. That is `curl` retransmitting across its three-second timeout, not three separate attempts — the same distinction Lab 03 drew between retransmission and scanning, now visible in TCP.

The difference from Lab 02 is the point. There, blocked pings went to an address where nothing existed. Here the server is alive and serving, and USERS still cannot reach it — by policy, not by absence.

## Administration without weakening the policy

Opening USERS → SERVERS on port 22 would have provided SSH access and undone what the isolation test had just demonstrated. The alternative used instead rests on a property of the chains: **traffic originating on the router does not traverse `forward`**. It goes through `output`, which is unfiltered.

So `router → srv-web` was already reachable while `ws-user01 → srv-web` was not, with no rule change required. The resulting path is `ws-user01 → lab-router → srv-web`: users cannot reach the server, an administrator can, through a controlled point.

Hardening was applied as a drop-in rather than by editing the main file, so local changes survive package upgrades without the conflict prompt the router produced in Lab 03:

    # /etc/ssh/sshd_config.d/hardening.conf
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    KbdInteractiveAuthentication no
    MaxAuthTries 3

Verified with `sshd -T`, and confirmed non-locking by opening a second session from the router before closing the first.

## Honest assessment of the access pattern

The pattern is right; this implementation of it is not production-grade, and the distinction is recorded rather than glossed.

Correct: administration does not originate from the user network, authentication is key-only, hardening lives in `sshd_config.d/`.

Laboratory shortcut: a router and a bastion are functions production separates. Collapsing them means compromising one yields the other — concentration of risk in the single device that also moves every packet. Worse, the jump key was generated *on the router*, so an administrative private key now lives on the routing device.

That shortcut is what [`lab-05-mgmt-bastion`](../lab-05-mgmt-bastion/) exists to correct. The value of recording it here is that the progression stays visible: a reasonable intermediate step, identified as a compromise, then resolved.

## The first log source

`srv-web` is the first host in the environment that generates security-relevant logs from real requests:

    ::1 - - [13/Aug/2026:14:48:28 +0100] "HEAD / HTTP/1.1" 200 0 "-" "curl/8.14.1"
    10.10.20.50 - - [13/Aug/2026:14:49:11 +0100] "HEAD / HTTP/1.1" 200 0 "-" "curl/8.14.1"

Two things about this log matter for what follows. The blocked attempt from `ws-user01` **does not appear here** — it died at the router, so its only trace is the `FWD-DROP` entry in the router's log. Reconstructing a blocked attack requires correlating both. An analyst watching only the nginx log would see the traffic that got through and never the attack that was stopped, which is the concrete argument for centralising logs from every layer.

The user-agent is the other half. `curl/8.14.1` is a default signature; scanners identify themselves the same way unless deliberately masked, so an access log full of `sqlmap` or `nikto` user-agents is an un-obfuscated scan and a natural first detection rule. The response headers nginx returns — `Server: nginx`, `Content-Length`, `ETag`, `Last-Modified` — are the reciprocal: reconnaissance an attacker collects about this server. Suppressing them is a later hardening item.

## Verification

| Test | Result |
|---|---|
| `ping 10.10.20.1` from `srv-web` | Replies, `ttl=64` |
| `ping 8.8.8.8` from `srv-web` | Replies, `ttl=62` |
| `curl -I http://localhost` on `srv-web` | `HTTP/1.1 200 OK`, `Server: nginx` |
| `curl -I http://10.10.20.50` from `ws-user01` | Timeout after 3011 ms, `curl (28)`, logged |
| `ssh vboxuser@10.10.20.50` from `lab-router` | Connects by key, no password |
| `sshd -T` on `srv-web` | `permitrootlogin no`, `passwordauthentication no`, `maxauthtries 3` |

The `ttl=64` / `ttl=62` pair is the evidence for the network path: 64 means the gateway replied directly with no hop consumed, 62 means two hops — the router, then VirtualBox's NAT engine — matching the value established in Lab 02. A host that had never existed before gained internet access without a single change to the router.

## Contents

    lab-04-srv-web/
    ├── README.md
    ├── logbook.md
    ├── configs/                      [pending collection]
    │   ├── listening-sockets.txt     ss -tlnp on srv-web, nginx and sshd
    │   ├── sshd-hardening.txt        sshd -T, the four hardened directives
    │   └── network-config.txt        ip -br addr and ip route on srv-web
    └── logs/                         [pending collection]
        ├── nginx-access.log          The first requests served
        └── router-fwddrop.log        The blocked USERS → SERVERS attempt

The capture commands were run during the session but the files were never extracted. `srv-web` has no shared folder configured, so they have to leave via the router before following the usual route to the Mac:

    srv-web → lab-router → /media/sf_shared
    mount_smbfs //agr86@192.168.0.41/vbox-shared ~/smbtest

## Status and continuation

Complete. SERVERS is no longer empty, isolation is verified against a live service, and administration works through a bastion jump without weakening the policy. Snapshot `sesion04-srv-web-ok`.

**Lab 05:** separate the bastion from the router. The pattern used here is correct and its implementation is not — a dedicated management segment with a purpose-built host removes the administrative key from the routing device and gives the environment a single controlled entry point.

Evidence collection for this lab remains outstanding and is tracked in the logbook.

> **Note:** the router-as-bastion shortcut described above was resolved in [`lab-05-mgmt-bastion`](../lab-05-mgmt-bastion/).
