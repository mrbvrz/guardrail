# Tools

Operational scripts for the DPMPTSP Pekanbaru 2026 migration (CentOS → Ubuntu 26.04 LTS).

| Tool | Purpose |
|---|---|
| [`migration-validate/`](migration-validate/README.md) | Validate rsync migration results per folder (multi-server profiles, checksum, TUI, logging). |
| [`hardening-check/`](hardening-check/README.md) | Audit and benchmark security hardening: SSH, firewall, web server, TLS/SSL, PHP, database, password policy, system/kernel. Cross-distro. |
| [`cve-check/`](cve-check/README.md) | CVE exposure assessment: advisory rules, distro security updates, optional OSV lookup. Cross-distro, offline-first. |

Reports and logs are written to [`result/`](result/).

## Typical order during maintenance

```bash
# 1. On the old CentOS server — capture a pre-migration baseline
sudo bash hardening-check/hardening-check.sh --benchmark --json > baseline-centos.json

# 2. On the destination Ubuntu server — validate migrated data
sudo bash migration-validate/migration-validate.sh --server srv1

# 3. Patch level check — which known CVEs are still open
sudo bash cve-check/cve-check.sh --benchmark --json > cve-ubuntu.json

# 4. After platform setup and before go-live — certify hardening
sudo bash hardening-check/hardening-check.sh --benchmark --json > baseline-ubuntu.json

# 5. Prove the improvement / catch regressions
sudo bash hardening-check/hardening-check.sh --benchmark --diff baseline-centos.json

# 6. Re-check quickly after each remediation batch (exit 0 = no CRITICAL/HIGH)
sudo bash hardening-check/hardening-check.sh --quick
sudo bash cve-check/cve-check.sh --severity HIGH
```

All scripts are read-only and need root only for full check coverage.
