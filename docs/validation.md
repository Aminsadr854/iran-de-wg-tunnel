# Release 2 validation and release gates

Version source: `VERSION` = **2.0.0**. Validation date: 2026-10-02.

| Gate | Result | Evidence / scope |
| --- | --- | --- |
| Security audit | PASS | Every tracked file, all 3 original commits and 63 historical blobs reviewed; no actual credentials found |
| Full history/current-tree secret scan | PASS | Gitleaks 8.30.1, redacted; no findings; scans repeated for release content |
| No tracked secrets | PASS | Index review, scanner, ignored runtime/credential artifacts |
| Production-specific runtime values removed | PASS | Current tree no longer contains original production public IPs/private layout/interface assumptions |
| Bash syntax | PASS | `bash -n` for every shell entry/test script |
| ShellCheck | PASS | ShellCheck 0.9.0; no findings |
| Python syntax | PASS | Every Python file compiled/parsed |
| Tests | PASS | 29 tests: config/security/layout/CPU/roles/OS, real key generation, firewall model, lifecycle failures, restore/upgrade/health |
| Dry-run | PASS | Foreign and Iran offline generator previews; no mutation calls; host-capability path is implemented but not verified on a clean root host |
| Install idempotency | PASS | Existing installation stops before key generation; rule/helper model converges without duplicates |
| Uninstall safety | PASS | Model/lifecycle assertions preserve unrelated rules/units, remove only recorded interfaces and keep packages |
| Secret redaction | PASS | Known private/PSK/raw/pair material; generic passwords, quoted values, authorization, key blocks/tokens |
| Generated systemd units | PASS | `systemd-analyze verify` in isolated root fixture with executable/base-unit stubs; syntax/dependencies only |
| Documentation/public sanity | PASS | Setup, pairing, ports, requirements, limitations, commands, operations, security, troubleshooting, benchmarks |
| Version | PASS | Public CLI reads single VERSION file |
| Clean-host live install | **NOT PERFORMED** | Workspace lacks root privileges and booted systemd; no dedicated test hosts were supplied |
| Current production servers modified | **NO** | No production SSH, service, firewall, routing or key operations |

## What “PASS” means here

**STATICALLY VERIFIED:** generators and safety logic reviewed, shell/Python syntax checked, ShellCheck, secret scans, generated systemd syntax. **UNIT TESTED:** pure allocation/parsing/validation, actual `wg genkey/genpsk/pubkey`, simulated iptables state and mocked operating-system lifecycle/rollback. **DRY-RUN VERIFIED:** offline output for both roles with mutation functions asserted unused. A pinned udp2raw native build succeeded in a temporary local directory, without starting it as a carrier.

**LIVE TESTED on clean servers: no.** No live TCP/UDP traffic, full host preflight, real firewall enforcement, systemd reboot persistence or end-to-end installation was tested for the new installer. Underlying **PRODUCTION PROVEN ARCHITECTURE** comes from the owner's original deployment/reference measurements; it does not substitute for portable-installer integration testing.

The requested publication gates cover the static/unit/dry-run checks above. Clean-host testing remains a documented follow-up rather than being represented as a pass. Compatibility targets are Ubuntu LTS 22.04/24.04/26.04 and Debian 12/13 on x86_64/aarch64; live platform certification remains pending.

## Reproduce local checks

```bash
# Distribution prerequisites for validation tools:
sudo apt-get install -y shellcheck wireguard-tools
./tests/run.sh
./install.sh --dry-run --offline --config config.example.env
./install.sh --dry-run --offline --role iran
python3 scripts/tunnelctl.py version
```

Without `wg`, the optional real-key test explicitly skips; without ShellCheck the runner explicitly reports unavailable. The release run had both tools present, no skips. GitHub CI installs them and runs static/offline tests without invoking installation.

For a new security audit, install a trusted Gitleaks binary and run:

```bash
gitleaks git . --log-opts="--all --full-history" --redact --no-banner
gitleaks dir . --redact --no-banner
git fsck --full --no-reflogs
git diff --check
```

On **dedicated disposable supported hosts**, future live verification should include preflight/dry-run, Foreign/Iran bootstrap, application TCP+UDP/DNS concurrently, all three handshakes/counters, reboot persistence, a single-carrier failure, bounded opt-in recovery, repair/upgrade identity preservation, backup/restore, repeated installation refusal and uninstall preserving seeded unrelated firewall/routes/services. Keep production entirely out of that procedure.
