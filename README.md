# Tools

Operational scripts for the DPMPTSP Pekanbaru 2026 migration (CentOS → Ubuntu 26.04 LTS).

| Tool | Purpose |
|---|---|
| [`migration-validate/`](migration-validate/README.md) | Validate rsync migration results per folder (multi-server profiles, checksum, TUI, logging). |
| [`hardening-check/`](hardening-check/README.md) | Audit and benchmark security hardening: SSH, firewall, web server, TLS/SSL, PHP, database, password policy, system/kernel. Cross-distro. |
| [`cve-check/`](cve-check/README.md) | CVE exposure assessment: advisory rules, distro security updates, optional OSV lookup. Cross-distro, offline-first. |
| [`threatscan/`](threatscan/README.md) | Threat/malware scan for PHP web roots: YARA rules, entropy analysis, heuristic scoring, quarantine, Git-aware scans. Console, JSON, SARIF, HTML and JUnit output. |

## Requirements

- bash, find, grep, sed, awk — all tools.
- `jq` — required by `threatscan` only; the audit tools need no extra runtime.
- Optional for `threatscan`: `yara`/`yarac`, `php-cli`, `parallel`, `git`, `curl`, `clamscan`.

Verify a host before the first run (none of these touch servers or files):

```bash
bash threatscan/threatscan.sh --check-deps
bash cve-check/cve-check.sh --self-test
bash hardening-check/hardening-check.sh --self-test
bash migration-validate/migration-validate.sh --self-test
```

## Output

Every output path is git-ignored.

| Tool | Default location |
|---|---|
| `cve-check`, `hardening-check`, `migration-validate` | `result/` in the repository root |
| `threatscan` | `threatscan/reports/` for reports, `threatscan/logs/` for logs |

`threatscan` prints to the console only; add formats with e.g. `--output console,html,json`. Its exit code follows `--fail-on` (default `HIGH`): `0` below the threshold, `1` MEDIUM/LOW, `2` HIGH, `3` CRITICAL.

## Typical order during maintenance

```bash
# 1. On the old CentOS server — capture a pre-migration baseline
sudo bash hardening-check/hardening-check.sh --benchmark --json > baseline-centos.json

# 2. On the destination Ubuntu server — validate migrated data
sudo bash migration-validate/migration-validate.sh --server srv1

# 3. Scan the migrated web root for threats and backdoors
sudo bash threatscan/threatscan.sh /var/www/html --output console,html,json

# 4. Patch level check — which known CVEs are still open
sudo bash cve-check/cve-check.sh --benchmark --json > cve-ubuntu.json

# 5. After platform setup and before go-live — certify hardening
sudo bash hardening-check/hardening-check.sh --benchmark --json > baseline-ubuntu.json

# 6. Prove the improvement / catch regressions
sudo bash hardening-check/hardening-check.sh --benchmark --diff baseline-centos.json

# 7. Re-check quickly after each remediation batch (exit 0 = no CRITICAL/HIGH)
sudo bash hardening-check/hardening-check.sh --quick
sudo bash cve-check/cve-check.sh --severity HIGH
```

The three audit scripts are read-only; `threatscan` only modifies files when `--quarantine` is given. Root is needed for full check coverage.
