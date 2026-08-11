# Command reference

Running reference of commands used across the homelab, with what each one is actually for. Grouped by purpose rather than by session.

---

## Network inspection

| Command | Purpose |
|---|---|
| `ip -br link` | Interfaces and their MAC addresses, one line each. First step after cloning a VM — never assume the adapter→interface mapping. |
| `ip -br addr` | Addresses, abbreviated. Prints all addresses of an interface on one line; a narrow terminal truncates it, so an address can appear missing when it is not. Good for scanning, unreliable for concluding. |
| `ip addr show <iface>` | Full view of one interface. Use this to confirm anything the brief view seems to show. |
| `ip route` | Routing table. `proto kernel` = auto-generated on address assignment; `proto dhcp` = learned; `proto static` = configured deliberately. |
| `ip neigh` | ARP neighbour table: which MAC answers for which IP, and the entry's state (`REACHABLE`, `STALE`). |
| `ip neigh flush all` | Clears the neighbour table. Does not stay clear — a default gateway entry re-resolves within milliseconds, because any outbound traffic needs it. |
| `ping -c<n> <host>` | Send `n` ICMP echo requests. `ttl=64` in the reply means zero routing hops; `63` means one. |
| `nc -zv <host> <port>` | Is a port open and reachable. `-z` scans without sending data. Separates a firewall problem from a credentials problem. |

## Network configuration (NetworkManager)

Debian 13 uses NetworkManager, not `ifupdown`. Editing `/etc/network/interfaces` has no effect.

    nmcli connection add type ethernet ifname enp0s8 con-name seg-users \
      ipv4.method manual ipv4.addresses 10.10.10.1/24 \
      ipv6.method disabled connection.autoconnect yes

| Command | Purpose |
|---|---|
| `nmcli con show` | All profiles. The `DEVICE` column shows `--` for inactive ones. |
| `nmcli con up <name>` / `down <name>` | Activate / deactivate a profile. |
| `nmcli con delete <name>` | Remove a profile. Orphaned profiles inherited from cloning can reactivate unexpectedly if the intended one fails to come up. |
| `nmcli -t -f NAME,DEVICE,TYPE,STATE con show` | Machine-readable output for scripting. The field list takes **no spaces** after commas. |
| `nmcli -f ipv4.method,ipv4.addresses con show <name>` | Inspect specific fields of a saved profile — what is stored, as opposed to what is applied. |

Abbreviations work: `nmcli con add`, `nmcli c s`. Fewer keystrokes, fewer typos.

**Gateway rule:** only the client carries `ipv4.gateway`. A router's internal legs must not — only one default route can exist per table, and the kernel generates connected routes automatically on address assignment.

Profiles are stored in `/etc/NetworkManager/system-connections/`. Those raw files will eventually contain secrets (Wi-Fi PSKs, VPN credentials) — never commit them.

## System identity

| Command | Purpose |
|---|---|
| `hostname` | Which machine am I on. |
| `hostnamectl set-hostname <name>` | Set the system hostname persistently. Update `/etc/hosts` to match, or `sudo` stalls on name resolution. |
| `uname -r` | Running kernel version. |
| `. /etc/os-release && echo "$PRETTY_NAME"` | Distribution and release. Sourcing the file exposes its variables to the shell. |

## Kernel parameters

| Command | Purpose |
|---|---|
| `sysctl net.ipv4.ip_forward` | Read a kernel parameter. Lives in `/usr/sbin`, absent from a normal user's `PATH` — needs `sudo` or the full path. |
| `cat /proc/sys/net/ipv4/ip_forward` | Same value, read directly. `sysctl` is a convenience layer over `/proc/sys/`: replace dots with slashes. Works without `sudo` and on minimal systems where `sysctl` is not installed. |

## Traffic capture

| Command | Purpose |
|---|---|
| `tcpdump -ni <iface> arp` | Live ARP capture. `-n` skips name resolution (faster, no DNS noise), `-i` selects the interface. |
| `tcpdump -ni <iface> arp -w file.pcap` | Write the raw capture to disk. The binary keeps every field; a text rendering is an interpretation of it. |
| `tcpdump -nr file.pcap` | Read a capture back. Status messages go to stderr, so `>` produces a clean text file. |

Check `packets dropped by kernel` on exit. Anything above zero means the buffer overflowed and quantitative analysis of that capture is invalid.

`tcpdump` writes as root, so `chown` the output before trying to copy it out as a normal user.

## Services

| Command | Purpose |
|---|---|
| `systemctl restart <service>` | Apply a configuration change. Editing a config file alone does nothing. |
| `systemctl is-active <service>` | Confirm the service survived the change. A syntax error can leave it dead. |
| `systemctl status <service>` | Full state, including recent log lines. |

## SSH

| Command | Purpose |
|---|---|
| `ssh-keygen -t ed25519 -C "comment" -f ~/.ssh/keyname` | Generate a keypair. `-f` sets the path non-interactively; without it, `ssh-keygen` prompts for a location and asks before overwriting an existing key. One key per destination — compromise one, revoke one. |
| `ssh-copy-id user@host` | Install the public key into the remote `authorized_keys` with correct permissions. Doing it by hand is where 700/600 mistakes happen. |
| `ssh-copy-id -i key.pub -f user@host` | Force installation of a specific key, skipping the already-present check. |
| `ssh -T git@github.com` | Test authentication without opening a shell. |
| `sshd -T` | Dump the **effective** configuration, already resolved, in lowercase. `grep` on the config file shows what a file says; this shows what the daemon has loaded. They diverge whenever an edit was made without a restart. |
| `dpkg-reconfigure openssh-server` | Regenerate host keys after deleting them. |

**Hardening in `/etc/ssh/sshd_config`:** `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `MaxAuthTries 3`. Applies with `systemctl restart ssh`.

**Client config in `~/.ssh/config`** — which key to use per host:

    Host github.com
       HostName github.com
       User git
       IdentityFile ~/.ssh/id_ed25519_github
       IdentitiesOnly yes

`IdentitiesOnly yes` matters: without it the client offers every key it finds, and the server can reject you for too many attempts. The file must be `chmod 600` or SSH ignores it.

**Post-clone step, mandatory** — clones inherit host keys, so two machines present the same cryptographic identity:

    sudo rm /etc/ssh/ssh_host_*
    sudo dpkg-reconfigure openssh-server

**Temporarily relaxing a control** — open, verify the service survived, use, close, then verify the *effective* state with `sshd -T`. Step five is the one that gets skipped, and the gap between file and daemon is exactly what an audit finds.

## File transfer

| Command | Purpose |
|---|---|
| `scp source user@host:~/` | Copy to a remote host. The **colon** is what makes a path remote — omit it and you get a local file with an odd name. |
| `scp user@host:~/file ./` | Copy from a remote host. Requires a key authorised in that direction; authorisation is not symmetric. |
| `scp -r source user@host:~/` | Recursive, for directories. |
| `mount_smbfs //user@host/share ~/mountpoint` | Mount an SMB share on macOS from the terminal. Gives a specific error where Finder only says "access denied". |
| `mount \| grep smb` | Where an SMB share is actually mounted. Only Finder mounts under `/Volumes/`; `mount_smbfs` mounts where you tell it. |
| `security delete-internet-password -s <host>` | macOS: remove cached credentials from the keychain. Without this, Finder silently resends stale ones. |

`mount_smbfs` error meanings: `Authentication error` = credentials rejected; `No such file or directory` = the share does not exist; `Permission denied` = share exists, auth succeeded, no access rights; timeout = firewall blocking port 445.

## Files and permissions

| Command | Purpose |
|---|---|
| `chmod 600` / `700` | Private key and `~/.ssh` directory respectively. SSH refuses to use a key with looser permissions. |
| `chmod 644` | Normal readable file. Text files should not carry the execute bit — Git records it and GitHub displays it. |
| `chown $USER file` | Take ownership. Files created under `sudo` belong to root and cannot be copied out as a normal user. |
| `usermod -aG <group> $USER` | Add to a group. The `-a` is critical: without it, existing groups are **replaced**. Requires re-login to take effect. |
| `cp -r source dest/` | Recursive copy. `cp` accepts multiple sources when the last argument is a directory. |
| `mkdir -p path` | Create a directory, no error if it already exists. |
| `ls -la` | Long listing including hidden entries. Files starting with a dot are invisible without `-a`. |

## Packages

| Command | Purpose |
|---|---|
| `which <command>` | Is a binary present, and where. Returns nothing if absent. |
| `apt update && apt install -y <pkg>` | Install a package. Requires working external connectivity — diagnose the network first if it fails. |

## Text processing

| Command | Purpose |
|---|---|
| `grep -n "pattern" file` | Search with line numbers. |
| `grep -rn "pattern" dir/` | Recursive search across a directory tree. |
| `grep -riE "password\|secret\|token" dir/` | Case-insensitive extended search. Run this over anything before publishing it. |
| `sed -i 's/old/new/' file` | In-place substitution. **On macOS `-i` requires an argument**: `sed -i '' 's/…/…/'`. A BSD/GNU difference that bites when alternating between Mac and Debian. |
| `sed -i '0,/pattern/{/pattern/d}' file` | Delete only the **first** match; the `0,/pattern/` range is what limits it. **GNU sed only** — BSD sed rejects line address 0. |
| `find . -type f` | List files only, excluding directories. The dash in `-type` is not optional. |
| `find ~ -name "x" -not -path "*/Library/*" 2>/dev/null` | Search a home directory, excluding macOS caches and silencing permission errors. |
| `mdfind -name "x"` | macOS only. Queries the Spotlight index — instant, versus `find` walking the disk. |
| `head -n <file>` / `tail -n <file>` | First / last lines of a file. |
| `pbcopy < file` / `pbpaste` | macOS clipboard from the terminal. `pbcopy` is silent on success — verify with `pbpaste`. |

## Redirection and shell operators

| Operator | Effect |
|---|---|
| `>` | Create or **overwrite**, stdout only. This is why `tcpdump`'s status line — written to stderr — never contaminates a redirected capture. |
| `>>` | Append. Using `>` mid-sequence destroys everything written before it. |
| `2>/dev/null` | Discard stderr, leaving stdout intact. |
| `&&` | Run the next command **only if** the previous succeeded. |
| `\|` | Pipe stdout of one command into stdin of the next. |
| `$(command)` | Command substitution — insert the output inline. No space between an option and its letter: `$(date -Is)`, not `$(date - Is)`. |
| `{ cmd; cmd; } > file` | Group commands and redirect their combined output once. |

`~` is the home directory; `~/.ssh` is correct, `~./ssh` is not. In zsh, `~` followed by text means *that user's* home, which is why the error mentions a user rather than a file.

## VirtualBox

| Command | Purpose |
|---|---|
| `VBoxManage snapshot <vm> take "name"` | Snapshot. Runs on the **host**, never inside the guest — a VM has no control over its own hypervisor. |
| `VBoxManage snapshot <vm> list` | List existing snapshots. |

Snapshot with VMs powered off: capturing them running also stores RAM, adding gigabytes and restoring to a machine mid-execution.

When cloning, always select **Generate new MAC addresses for all network adapters**. Duplicate MACs on one segment cause intermittent ARP conflicts — the kind that work for a while and then stop for no visible reason, which is harder to diagnose than a clean failure.

Shared folders mount at `/media/sf_<name>` and require membership of the `vboxsf` group. Ownership and permissions there are imposed by the VirtualBox driver, not the guest kernel — which is why `usermod -aG vboxsf` is required despite the copy being made by your user.

Guest Additions are required for shared folders and bidirectional clipboard. Enable the clipboard via **Devices → Shared Clipboard → Bidirectional**; it removes an entire class of transcription errors.

### Post-clone procedure

A clone is not a new machine until its inherited identity has been replaced. Four steps, all of them mandatory:

**1. Regenerate MAC addresses** — at clone time, select *Generate new MAC addresses for all network adapters*. Duplicate MACs on one segment cause intermittent ARP conflicts, which are harder to diagnose than clean failures.

**2. Set the hostname**

    sudo hostnamectl set-hostname <name>
    sudo nano /etc/hosts        # update the 127.0.1.1 line to match

Without the `/etc/hosts` update, `sudo` stalls on name resolution.

**3. Regenerate SSH host keys**

    sudo rm /etc/ssh/ssh_host_*
    sudo dpkg-reconfigure openssh-server

When prompted about a modified `sshd_config`, choose **keep the local version currently installed** — the maintainer's version silently reverts any hardening.

Verify afterwards:

    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub    # fingerprint and comment
    sudo sshd -T | grep -E "permitrootlogin|passwordauthentication"
    systemctl is-active ssh

The key comment should show the new hostname, not the template's.

**4. Remove orphaned NetworkManager profiles**

    nmcli con show                    # look for inherited profiles with `--` under DEVICE
    sudo nmcli con delete "Wired connection 1"

An inactive profile with `autoconnect` enabled can activate itself if the intended one fails, handing you a configuration different from the one you believe is applied.


## Git

| Command | Purpose |
|---|---|
| `git init` | Initialise a repository in the current directory. |
| `git config --global user.name "Name"` | Identity signed into every commit. |
| `git config --global user.email "email"` | Must match the GitHub account, or commits appear unattributed. |
| `git config --global init.defaultBranch main` | Default branch name for new repositories. |
| `git status` | What has changed and what is staged. The last checkpoint before publishing — read it, do not skip it. |
| `git add .` | Stage everything not excluded by `.gitignore`. |
| `git commit -m "message"` | Record with a descriptive message. `lab-01: add ARP capture evidence`, not `update`. |
| `git log --oneline --decorate` | History. `(HEAD -> main, origin/main)` means the commit reached the remote; its absence means it is still local. |
| `git branch -M main` | Rename the current branch. |
| `git remote add origin <url>` | Attach a remote. Fails if one already exists. |
| `git remote set-url origin <url>` | Change an existing remote's address. |
| `git remote -v` | Where the remote points. `git@` = SSH, uses your key; `https://` = prompts for credentials every time. |
| `git push -u origin main` | First push, establishing tracking. Afterwards `git push` suffices. |

Create the repository on GitHub **empty** — no README, no `.gitignore`, no licence. An initialisation commit there plus a commit locally produces two histories with no common ancestor, and the first push fails with an unhelpful message.

`.gitignore` from the first commit:

    *.key
    *.pem
    id_*
    *.nmconnection
    *.vdi
    *.ova
    *.qcow2
    .DS_Store

## Session hygiene

| Command | Purpose |
|---|---|
| `hostname` | Which machine am I on. The window title identifies the VM, not the shell — once SSH is involved, those decouple. Run it before any command whose effect depends on where it executes. |
| `exit` | Leave an SSH session and return to the local shell. |
| Tab key | Path completion. Doubles as verification: if it does not complete, the path does not exist. |

Read **who** emits an error, not only what it says. `Destination Host Unreachable` on a local network comes from the *source* machine when nobody answers its ARP request — a loud, local failure. A packet dropped by a router with `ip_forward = 0` produces nothing at all — a silent, remote failure. That distinction places the fault on one side of the link before touching any configuration.

Diagnose outward from the host; the first failing step localises the problem:

    ip addr        → does the interface have an address?
    ip route       → is there a route to the destination?
    ping gateway   → does the next hop answer?
    ping 8.8.8.8   → external reachability?
    ping a domain  → if the previous worked and this fails, it is DNS
