# Captures — Session 1

Evidence of ARP resolution on the USERS segment. It demonstrates that layer 2 communication between `ws-user01` and `lab-router` works, which in turn confirms that the failure toward `8.8.8.8` is not a link problem but an IP forwarding one.

## How to reproduce it

Both VMs running. **On `lab-router`**, leave the capture running:

```bash
sudo tcpdump -ni enp0s8 arp -w /tmp/arp-users.pcap
```

**On `ws-user01`**, flush the ARP cache to force a fresh resolution and generate traffic:

```bash
sudo ip neigh flush all
ping -c3 10.10.10.1
```

Back on `lab-router`, stop with `Ctrl+C` and also produce a human-readable text version:

```bash
tcpdump -nr /tmp/arp-users.pcap > /tmp/arp-users.txt
```

Copy both files into this directory from the host:

```bash
scp user@10.10.10.1:/tmp/arp-users.{pcap,txt} ./
```

## What you should see

One request/reply pair for each address resolved:

```
ARP, Request who-has 10.10.10.1 tell 10.10.10.10, length 28
ARP, Reply 10.10.10.1 is-at <router MAC>, length 46
```

The request is a broadcast: `ws-user01` asks the entire segment who holds that IP. The reply is unicast: only the router answers, and it answers the requester directly.

If the request appears but the reply does **not**, the problem is at the far end (VM powered off, adapter on the wrong internal network, or interface down). That was exactly the symptom of failure 1 documented in the logbook.

## Files

| File | Contents |
|---|---|
| `arp-users.pcap` | Binary capture, openable in Wireshark |
| `arp-users.txt` | Text dump for direct reading |
