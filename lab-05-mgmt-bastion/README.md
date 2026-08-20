# Lab 05 — Management segment and bastion

Continuation of [`lab-04-srv-web`](../lab-04-srv-web/). That lab reached SSH administration of `srv-web` by using the router itself as a jump host, and flagged the arrangement as a laboratory shortcut: a router and a bastion are functions production separates, because collapsing them means compromising one hands you the other. Worse, the administrative private key was generated on the routing device.

This lab does that piece properly. A dedicated management segment — `intnet-mgmt`, `10.10.99.0/24` — with a purpose-built bastion, `mgmt-01`, becomes the single controlled entry point for administration. The router is then removed as a bastion in three independent layers, so that it forwards packets and no longer terminates administrative sessions.

The lab's most useful material came not from what worked but from attacking what had just been built. The session-recording mechanism installed here is defeated, deliberately, in one command.

## What it demonstrates

| Capability | Mechanism |
|---|---|
| Dedicated management network | Fifth router leg `enp0s16` at `10.10.99.1`, `seg-mgmt` NM profile |
| Purpose-built bastion | `mgmt-01` at `10.10.99.10`, desktop purged, minimal surface |
| Encrypted admin path from the laptop | ProxyJump through `mgmt-01`; the jump host never sees the credential |
| External reach without a second unfiltered egress | NAT port-forward → DNAT on the router, not a second adapter |
| Router removed as bastion | Credential revoked, `ListenAddress` restricted, `input` chain closed |
| Session activity recorded on the bastion | `script` via `/etc/profile.d`, with its limitation demonstrated |
| IPv6 denied by policy, not by absence | `ip6` table with `policy drop` on all three chains |

## Building the segment

The router already carried four adapters, and the VirtualBox GUI caps at four tabs. The limit is in the interface, not the hypervisor:

    VBoxManage modifyvm lab-router --nic5 intnet --intnet5 "intnet-mgmt"

The new leg was then configured with an explicit `seg-mgmt` profile — `ipv4.method manual`, IPv6 disabled, interface name pinned — applying the orphaned-profile lesson from Lab 02.

Bringing the segment into existence granted it nothing. With `forward` at default-deny, `mgmt-01`'s installer could not even resolve a hostname:

    wget: unable to resolve host address 'deb.debian.org'

The reflex was to suspect the segment name, the Lab 04 pattern. It was neither that nor the mirror: the router's firewall had no rules for `enp0s16` at all, so management DNS queries were being dropped in silence. The fix is also the deliberate egress policy — 53, 80 and 443 only, so the bastion can update itself and do nothing else.

That is default-deny behaving exactly as designed. A permissive default would have made the segment work immediately and demonstrated nothing.

One consequence of that policy misleads later and is worth stating plainly: **`mgmt-01` answers no pings while having working internet access.** ICMP is not in the permitted set. Reachability here is per-protocol, not a single boolean, and reaching for `ping` as a first test on a filtered host returns a confident wrong answer.

## Placement, not just presence

The lab's most instructive failure happened twice, in two different chains, and the second time was after the first had already been diagnosed.

`nft add rule` appends to the **end** of a chain. Both filter chains end with an explicit logging drop that has no match criteria, so it catches everything reaching it:

    counter log prefix "FWD-DROP: " drop

A rule appended after that sits in dead ground. It is syntactically valid, it appears in `nft list ruleset`, and it is never evaluated. The first occurrence was the rule permitting SSH from the management segment, in `input`; the second was the rule permitting DNAT'd traffic through to `10.10.99.10:22`, in `forward`.

The fix is explicit positioning against a handle from `nft -a list chain`:

    nft insert rule ip lab-filter forward position 9 <rule>

Note the asymmetry: `insert ... position N` places the rule *before* handle N, while `add ... position N` places it *after*.

In an ordered ruleset, existence and effect are different properties. Confirming that a rule appears in the output confirms nothing about whether it runs — the check is its position relative to the terminating rule, or better, its packet counter under live traffic. The parallel to a detection rule that never fires is exact, and it is the reason this lab records the failure rather than quietly fixing it.

## The access path

The laptop reaches the bastion through a chain that keeps `mgmt-01` single-homed:

    macOS 192.168.0.129
      → 192.168.0.41:2222         Windows host, VirtualBox natpf1
      → 10.0.2.15:2222            lab-router NAT uplink
      → DNAT → 10.10.99.10:22     mgmt-01
      → ProxyJump → lab-router and, later, other segments

The obvious alternative — giving `mgmt-01` its own NAT adapter — was rejected. It would have opened a second, unfiltered route to the internet on the bastion and destroyed the property the management segment exists to guarantee: that all of its outbound traffic passes the 53/80/443 filter. The DNAT keeps one egress and turns the router from a session endpoint into a packet forwarder, which is a stronger claim than merely disabling logins because it is visible in `ss -lnt`.

ProxyJump matters for a reason worth stating: the jump host opens a TCP tunnel and the second SSH session authenticates end to end through it. `mgmt-01` never decrypts the laptop-to-router session and never sees the passphrase, which is why the laptop's private key never touches the bastion.

## Removing the router as a bastion

Three layers, each independent, because a control that depends on another control working is not a second layer.

**Credential.** `ws-user01-to-router` removed from the router's `authorized_keys`. That key was a valid administrative credential for the router, installed on a host in the USERS segment — compromising `ws-user01` would have yielded the router and through it every segment. Lateral movement by credential, found in the lab's own infrastructure.

**Service.** The three `ListenAddress` lines for `10.10.10.1`, `10.10.20.1` and `10.10.30.1` commented out rather than deleted, so the file records what was there before. sshd binds only to `10.10.99.1`.

**Firewall.** The `input`-chain rule accepting `tcp dport 22` from `{enp0s8, enp0s9, enp0s10}` deleted. A scan from those segments now receives a silent drop rather than a refusal — less information returned to a scanner, the distinction Lab 03 drew between `drop` and `reject`. ICMP from those segments is deliberately kept: ping is useful for diagnosis and grants no access.

The ordering was deliberate throughout. The new path was built and verified end to end before the old one was closed. Removing the router as a bastion while the only remaining access was the VirtualBox console would have been an empty gesture.

## Session recording, and its defeat

`script`, driven from `/etc/profile.d/session-recording.sh`, records every SSH session on `mgmt-01`. The trigger guards two failure modes:

    if [ -n "$SSH_CONNECTION" ] && [ -z "$SCRIPT_RECORDING" ]; then
        export SCRIPT_RECORDING=1
        LOGFILE="/var/log/session-logs/$(whoami)-$(date +%Y%m%d-%H%M%S)-$$"
        exec script -q -f -c "$SHELL -l" --timing="$LOGFILE.timing" "$LOGFILE.log"
    fi

`$SSH_CONNECTION` restricts recording to remote sessions, leaving the VirtualBox console — the recovery path — untouched. `$SCRIPT_RECORDING` prevents the shell that `script` launches from re-reading `/etc/profile.d` and spawning another `script`, which would loop until the machine stopped responding.

The directory is `chmod 1733` (write and traverse, no read or list) with `chattr +a` set. Neither is sufficient. `script` creates each log owned by the session user with write permission, and append-only on a *directory* prevents deleting or renaming entries while saying nothing about the contents of files inside it:

    $ wc -c vboxuser-20260814-121102-1467.log
    14040
    $ : > vboxuser-20260814-121102-1467.log
    $ wc -c vboxuser-20260814-121102-1467.log
    0

Fourteen kilobytes of an in-progress recording, erased without root, with the protection in place.

Worse than the truncation is what follows it. `script` still held the file open at offset 14040, so its next write landed there and the filesystem filled the gap with a sparse hole. By the next day the file measured 14234 bytes again — of which **194 are content and the rest are nulls**. Size, timestamp and a clean `COMMAND_EXIT_CODE="0"` all look correct. A zero-byte log is visibly wrong; one that refills itself is not.

A third failure closes the set: reading the log executes what it recorded. `script` captures control sequences verbatim, and the recorded session ended with `exit\r`, so displaying the file closed the reader's shell — four times, through `head`, `cat`, `cat -v` and `scriptreplay`. The last is not misuse: faithful replay means replaying the `exit`. Safe inspection means not treating the file as terminal output at all (`od -c`, `tr -d '\000'`).

The conclusion is recorded here rather than hidden. A session log kept on the same host where the audited user holds privileges is not tamper-resistant and cannot be made so by local means — and the log itself is untrusted input to whoever investigates it. The fix is to ship events off-host in real time, which is the job of the Wazuh agent in Lab 06.

This is also the lab's contribution to the method the detection phase formalises: **a control is attacked before it is trusted.** Two findings carry forward as worked detection cases once a SIEM exists — the `ws-user01` credential above, and this truncation.

## Verification

| Test | Result |
|---|---|
| `apt update` on `mgmt-01` | Succeeds — a functional test of the 53/80/443 filter |
| `ping 10.10.99.1` from `mgmt-01` | Replies, `ttl=64`, no decrement |
| `ssh -i id_ed25519_admin vboxuser@10.10.99.1` | Prompts for *key passphrase*, returns `lab-router` |
| `ss -lnt` on the router, after closing | One listener: `10.10.99.1:22` |
| `ssh mgmt-01` from macOS | Connects through natpf1 → DNAT |
| `ssh lab-router` from macOS | Connects via ProxyJump through the bastion |
| `rm` a session log | `Operation not permitted` |
| `: >` a session log | Succeeds — 14040 bytes to 0 |
| Same log, next day | 14234 bytes, of which 194 are content — the rest nulls |
| `head` / `cat -v` / `scriptreplay` on it | Reader's shell exits — recorded control sequences execute |
| Ruleset after a cold reboot | Identical: 32 lines, 5 accept rules, DNAT still ahead of the drop |

The passphrase prompt in row three is the diagnostic that matters. Had the router rejected the key, the prompt would have asked for the account password instead; asking for the passphrase means the key was accepted and only local decryption remained.

Package count fell 1571 → 1412 after the desktop purge, with `autoremove --dry-run` reporting nothing orphaned. Idle memory 291 MiB, consistent with a system carrying no graphical stack. The listening-socket count did not change — GNOME communicates over Unix sockets and D-Bus, so a desktop can carry dozens of services without opening a single TCP port. Surface reduction is real here but is not measured by `ss`.

## Contents

    lab-05-mgmt-bastion/
        ├── README.md
        ├── logbook.md
        ├── configs/
        │   ├── authorized-keys-fingerprints.txt   Three keys remaining on the router
        │   ├── nftables-ruleset.txt               Full ruleset with handles and rule order
        │   ├── session-recording.sh               The /etc/profile.d trigger
        │   └── sshd-listenaddress.txt             sshd -T, single bind after closing
        └── logs/
            ├── README.md                          Warning: the .log contains escape sequences
            ├── session-logs-listing.txt           Permissions showing why truncation was possible
            └── session-truncated.log              14234 bytes, 194 of content

## Status and continuation

The management segment is complete. The router is administrable only from `10.10.99.10`, closed in credential, service and firewall. `mgmt-01` is single-homed with no unfiltered egress. Session recording is in place with its limitation demonstrated rather than assumed.

Persistence is proven, not assumed. The router was rebooted on 2026-08-15 and every property held with no manual intervention: the ruleset returned identical (32 lines, 5 accept rules in `forward`, the DNAT rule still ahead of the drop), `nftables.service` ran `nft -f /etc/nftables.conf` to `status=0/SUCCESS`, and `ss -lnt` showed the single `10.10.99.1:22` listener. The three-layer closure survives a cold boot.

IPv6 is now denied rather than merely absent. Every router interface had it disabled through NetworkManager, but the kernel had it enabled and the absence rested on each profile carrying the right setting — the same fragility that left `enp0s16` without firewall rules when it was created. An `ip6` table with `policy drop` on `input`, `forward` and `output` covers any interface that appears without it. The table carries no rules and cannot be exercised, because no interface holds an IPv6 address to generate traffic with; that is the state of the verification, recorded rather than implied.

The router-as-bastion shortcut from Lab 04 is now fully undone. A forward rule permitting MGMT to reach USERS, SERVERS and DMZ on port 22 and ICMP — in one direction only — was added and verified by packet counter, and `lab-router-to-srv-web` was then revoked from `srv-web`, leaving `admin@mgmt-01` as its sole authorised credential. The router forwards packets and administers nothing.

That work produced a finding of its own: the Lab 04 key's passphrase was never recorded and is not recoverable, so before revocation it was an authorised credential nobody could use. Tracked in the Lab 04 logbook.

**Lab 06:** deploy the SIEM. Wazuh with agents on every host resolves the session-recording limitation by moving events off the machine that generates them, and turns the two findings above from observations into detections.

> **Note:** the off-host logging gap described above was partially addressed in [`lab-06-siem`](../lab-06-siem/) — collected events are now beyond a local attacker's reach, but session logs remain outside the collection path.
