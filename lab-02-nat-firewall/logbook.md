# Logbook — Lab 02: NAT and inter-segment filtering

---

## Session 2 — Forwarding, NAT, and default-deny filtering

**Date:** 2026-08-11 (lab) · 2026-08-13 (evidence and documentation)
**Duration:** ~5 h
**Module:** 1 — Networking for security

### Objective

Enable routing between the three segments and out to the internet, then restore inter-segment isolation through explicit policy rather than through the absence of forwarding. Make every configuration survive a reboot, and every denied packet visible in the logs.

### Steps performed

1. `net.ipv4.ip_forward = 1` written to `/etc/sysctl.d/99-lab-router.conf`, applied with `sysctl --system`.
2. Verified that forwarding alone did not restore connectivity, and captured why on the external interface.
3. `nftables` table `lab-nat` with a `postrouting` chain and a masquerade rule on `enp0s3`.
4. Verified translation with a second capture — same test, source address rewritten, replies returning.
5. Ruleset persisted to `/etc/nftables.conf`, service enabled.
6. `nftables` table `lab-filter` with a `forward` chain, `policy drop`, and three rules: `established,related`, internal-to-external, and a logging drop.
7. Verified isolation by pinging a non-existent host in SERVERS and reading the resulting log entries.
8. Rebooted and confirmed every property held with no manual intervention.
9. Snapshots `sesion02-inicio` and `sesion02-completa` with the VMs powered off.

### Result

Internal hosts reach the internet; segments cannot reach each other; every denial is logged. All of it survives a reboot.

---

### Failures and diagnosis

#### Failure 10 — An orphaned profile activating on the wrong interface

**Symptom:** after the first reboot, `ws-user01` could not reach the internet. The error had changed from previous sessions: `From 10.10.10.1 icmp_seq=1 Destination Net Unreachable`. On the router, `enp0s3` was `UP` with no address and there was no default route.

**First hypothesis, wrong:** that `Wired connection 1` had `autoconnect` disabled. It was set to `yes`.

**Actual cause,** found in `journalctl -u NetworkManager -b`:

    policy: auto-activating connection 'Wired connection 1'
    device (enp0s10): Activation: starting connection 'Wired connection 1'
    device (enp0s10): Activation: failed
    [repeating every 45 seconds]

NetworkManager was applying the profile to **`enp0s10`** — the DMZ leg — not to `enp0s3`. The profile had no `connection.interface-name` set, so it was considered applicable to any Ethernet device, and the one it chose already had `seg-dmz` active. It failed, retried indefinitely, and meanwhile the external leg was left unconfigured.

This is the inherited profile from cloning, documented in Lab 01 as a latent risk. The prediction there was that it "can activate itself if the intended one fails". It went further: it activated on an interface that was never its own.

**Fix** — replace rather than patch:

    sudo nmcli con delete "Wired connection 1"
    sudo nmcli con add type ethernet ifname enp0s3 con-name seg-nat \
      ipv4.method auto ipv6.method disabled connection.autoconnect yes

Naming it `seg-nat` brings it in line with `seg-users`, `seg-servers` and `seg-dmz`. Setting `ipv6.method disabled` also closed the IPv6 exposure on the external leg that Lab 01 had flagged and left open — the three SLAAC addresses disappeared from `enp0s3`.

**Takeaway:** a NetworkManager profile without `connection.interface-name` is not bound to anything. On a single-NIC machine that is harmless; on a multi-homed router it is a profile looking for somewhere to land. Every profile on a router must name its interface explicitly. And the diagnosis came from the logs, not from inspecting configuration — `nmcli con show` reported `autoconnect: yes` and told me nothing about *where* it was being applied.

#### Failure 11 — Persisting a ruleset that was already wrong

**Symptom:** after reboot, `nft list ruleset` showed the masquerade rule twice. Flushing and restarting the service did not clear it.

**Cause:** `nft list ruleset` faithfully reproduces what is in memory, including mistakes. The rule had been added twice at some point, and the dump to `/etc/nftables.conf` captured both. Every subsequent load reproduced the duplicate — it was not accumulating on load, it was written into the file.

**Secondary finding:** the first dump also captured live counter values (`counter packets 17 bytes 1156`), which are meaningless in a configuration file. `nft -s list ruleset` omits them.

**Fix** — clear memory, rebuild cleanly, verify, then persist:

    sudo nft flush ruleset
    [re-add table, chain and rule]
    sudo nft list ruleset          # confirm exactly one rule
    sudo sh -c 'printf "#!/usr/sbin/nft -f\n\nflush ruleset\n\n" > /etc/nftables.conf'
    sudo sh -c 'nft -s list ruleset >> /etc/nftables.conf'

**Takeaway:** persisting configuration is not the same as persisting *correct* configuration. Verify the running state before dumping it, because the dump has no judgement. The `flush ruleset` line at the top of the file matters for the same reason in reverse — without it, a reload adds to whatever is already in memory instead of replacing it.

Also relevant: `sudo nft ... > /etc/file` fails, because the redirection is performed by the unprivileged shell rather than by the elevated command. `sudo sh -c '...'` or `sudo tee` are the working forms.

#### Failure 12 — Predicted TTL 63, observed 62

**Symptom:** Lab 01 documented `ttl=64` as the zero-hop baseline and predicted 63 once forwarding was enabled. The measured value from `ws-user01` to `8.8.8.8` was 62.

**Cause:** the path crosses two routers, not one. `lab-router` decrements to 63, and VirtualBox's NAT gateway at `10.0.2.2` decrements again to 62. The gateway is a router; it was simply not drawn on the topology diagram.

**Takeaway:** TTL counts actual hops, not the ones in your documentation. The discrepancy between the two is information — in a production network it is what reveals infrastructure nobody recorded. The Lab 01 prediction was not a miscalculation but an incomplete model of the path, which is a more useful kind of error to have made.

#### Failure 13 — Log file empty because the journal does not persist

**Symptom:** `journalctl -k | grep FWD-DROP` produced an empty file when collecting evidence the following day.

**Cause:** with no `/var/log/journal` directory, systemd keeps the journal in memory only and discards it at shutdown. The default on this Debian install.

**Takeaway:** evidence that only exists in a volatile journal is not evidence. Either persist the journal (`sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal`) or export it before powering down. The same applies to `/tmp`, which is cleared on boot and took the first packet capture with it — that one had to be reproduced by temporarily flushing the NAT chain.

---

### Concepts consolidated

#### Forwarding and translation are separate functions

Enabling `ip_forward` makes the router relay packets between interfaces. It does nothing about the addresses those packets carry. A packet forwarded out of a private network still bears a private source address, and nothing outside that network can reply to it.

This was visible as a clean separation during testing: with NAT flushed but filtering intact, the counters showed traffic being **permitted** by the firewall and leaving the router — and still failing. The firewall decides whether a packet passes; NAT decides what return address it carries. Two independent questions.

#### Connection tracking is what makes NAT and stateful filtering possible

The router keeps a table of conversations in progress. It is what allows a reply addressed to `10.0.2.15` to be delivered back to `10.10.10.10`, and what allows `ct state established` to recognise a packet as belonging to a session that was already authorised.

The ICMP `id` field visible in both captures is the handle for this — the same `id 5` appears in request and reply, letting the router match them. With several internal hosts sharing one external address, that matching is the only thing keeping their traffic apart.

#### Rule order follows traffic volume

`established,related` is placed first because it matches most packets. A three-packet ping registered 1 hit on the outbound rule and 3 on `established` — only the opening packet is evaluated against the full policy; everything after belongs to a known conversation.

Later, with the client doing ordinary background work, `established` had counted 113 packets and 53 KB against 6 on the outbound rule. A host with connectivity is never quiet, and a firewall spends most of its time recognising traffic it has already decided about.

#### Default deny inverts where the effort goes

With `policy drop`, anything not explicitly permitted is refused. Adding a service later means writing a rule for it; forgetting means it does not work, which is a visible failure.

With default allow, forgetting means it works anyway — along with everything else nobody thought about, which is an invisible exposure. What is permitted should be a decision; what is denied can be the silence.

#### Blocking without logging is half the control

`policy drop` alone discards silently. The explicit `log prefix "FWD-DROP: " drop` rule at the end of the chain turns each refusal into a record with source, destination, both interfaces, protocol and timestamp.

That is the difference between a firewall as a barrier and a firewall as a sensor. The barrier stops one packet; the sensor tells you that a host in the user segment spent thirty seconds walking every address in the server range. Only the second is detection.

#### input and forward are different paths

Traffic addressed to the router traverses `input`. Traffic passing through it traverses `forward`. Filtering one does not affect the other.

`ping 10.10.20.1` from USERS still succeeds under a full `forward` deny policy, because that address belongs to the router and the packet never crosses between interfaces. The counters prove it: that ping appears in no rule of the filter table at all. Verifying a control means verifying it against the path it actually governs.

### Outstanding

- [ ] Filter the `input` chain — the router currently accepts all traffic addressed to itself, from every segment
- [ ] Restrict sshd with `ListenAddress`; it is bound to `0.0.0.0:22` and reachable from the external leg
- [ ] Deploy a host in SERVERS so inter-segment isolation can be tested against a live destination
- [ ] Persist the systemd journal so security-relevant logs survive a reboot
- [ ] Consider an IPv6 filtering policy, or document its absence as deliberate
