# Ownership, transactions and recovery

One installation per host is recorded by `/etc/icmp-tunnel/state.json`, schema 1 and a project ownership marker. New installation refuses unrecognized existing paths, interfaces, units, chains and overlapping routes. Repeat installation stops and points to repair/upgrade, preserving identities. Management mutations use a root-owned nonblocking process lock. Systemd firewall callbacks use a separate lock so starting services during installation does not deadlock the installer.

Owned resources:

- `/opt/icmp-tunnel` code and pinned binary, `/usr/local/bin/tunnelctl` wrapper.
- `/etc/icmp-tunnel/{state.json,peer.json,wg/,raw/}` protected configuration.
- `/etc/systemd/system/icmp-tunnel-*` units generated for the recorded carriers only.
- `/etc/sysctl.d/90-icmp-tunnel.conf` and saved original live values.
- Interfaces `wg9094` onward and their connected /30 routes.
- Firewall chains `IT2_DNAT`, `IT2_SNAT`, `IT2_FWD`, `IT2_INPUT`, `IT2_MSS`, and precisely marked hooks.
- `/var/lib/icmp-tunnel` health/transaction state and separately retained secret backups.

No broad IP rules/default routes, SSH settings, application credentials, external firewall policies or unrelated interfaces are installed or removed. Uninstall leaves distribution packages, shared kernel modules and existing secret backups. It restores a sysctl only if its current value still equals the project's applied value; changes made independently by administrators take precedence. Persistent settings in other sysctl files are never edited.

New installation performs read-only preflight, installs prerequisites and repeats resource checks, stages/builds code, then records original values/transaction intent before creating runtime resources. Caught errors and interrupts trigger project cleanup. Packages and shared module loads remain; they are not safe to blindly remove. Power loss, SIGKILL and OS failure cannot be made fully transactional.

Repair, upgrade and restore make a credential backup, then snapshot code/configuration under root-only `/var/lib/icmp-tunnel/update-*`. Update stops this project's services, re-renders and starts them. On failure it restores the snapshot. If rollback itself fails, it copies a retained `failed-update-*` snapshot and records its location. Transaction snapshots contain secrets and must never be uploaded.

An interrupted transaction intentionally blocks further repair/upgrade. Inspect `/var/lib/icmp-tunnel/transaction.json` as root to locate any recorded snapshot. On a failed new installation, `sudo /path/to/checkout/install.sh --uninstall --yes` removes its partial resources and saves credentials first when valid state exists. For an interrupted update, preserve the recorded snapshot and a secret backup, remove the partial installation using the checkout uninstaller, reinstall the matching role/public layout on this non-production host, and use the matching backup to restore identities. Keep the pair consistent. Do not copy a snapshot wholesale over unrelated host configuration. If state is damaged, review recorded resources manually instead of assuming ownership.

Repair/restore/upgrade cause downtime and can interrupt existing flows. They are meant for installations created by Release 2; there is no automatic adoption or mutation of the historical production deployment. Carrier failure does not switch established flows, and the default timer only monitors until SELF_HEAL is enabled.
