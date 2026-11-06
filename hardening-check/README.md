# Hardening Check

A cross-distribution Linux **security hardening assessment and benchmark** script. It audits SSH, firewall, web server, TLS/SSL, password policy, and system/kernel posture, then produces a weighted score and letter grade.

Designed for the DPMPTSP Pekanbaru migration: run it on the **new Ubuntu 26.04 LTS** server after cut-over, and on the **old CentOS** host to capture a baseline. It works on Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, Fedora, SUSE and Arch because every check detects the available tooling instead of assuming one distro.

---

## 1. Files

| File | Purpose |
|---|---|
| `hardening-check.sh` | Main assessment script |
| `README.md` | This document |

Reports are written to `tools/result/hardening-<host>-<timestamp>.log`.

---

## 2. Requirements

- Linux with Bash 4+
- Run as **root** for full coverage (`sudo`); without root some checks are skipped
- No external dependencies. `openssl`, `ss`, `systemctl`, `ufw`/`firewalld`, `php`, `fail2ban-client` are used **if present**, otherwise the related check reports `SKIP`/`INFO`
- macOS/BSD is tolerated for inspection (checks degrade to `SKIP`), but the tool targets Linux

---

## 3. Usage

```bash
# Full assessment (default)
sudo bash hardening-check.sh

# One section at a time
sudo bash hardening-check.sh --ssh
sudo bash hardening-check.sh --firewall
sudo bash hardening-check.sh --web
sudo bash hardening-check.sh --tls
sudo bash hardening-check.sh --password
sudo bash hardening-check.sh --php
sudo bash hardening-check.sh --db
sudo bash hardening-check.sh --system

# Full + benchmark grade
sudo bash hardening-check.sh --benchmark

# Fast pass (skips package-update, auth-log and certificate scans)
sudo bash hardening-check.sh --quick

# Machine-readable output (for dashboards/CI)
sudo bash hardening-check.sh --json

# Custom report location
sudo bash hardening-check.sh --report /var/log/hardening.log

# Compare against a previous JSON report (regressions / fixed findings)
sudo bash hardening-check.sh --benchmark --diff baseline.json

# Treat documented risks as accepted (do not block go-live)
sudo bash hardening-check.sh --benchmark --accept SSH-03,SSH-08

# Verify the script itself without touching the system
bash hardening-check.sh --self-test
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | No CRITICAL/HIGH failures (accepted IDs excluded) |
| `1` | At least one non-accepted CRITICAL/HIGH failure |
| `2` | Usage error |

---

## 4. What Is Checked

### SSH hardening (`--ssh`)

| ID | Check |
|---|---|
| SSH-01 | SSH service running |
| SSH-02 | SSH enabled at boot |
| SSH-03 | `PermitRootLogin` (direct root login) |
| SSH-04 | `PubkeyAuthentication` enabled |
| SSH-05 | `PasswordAuthentication` disabled (key-only) |
| SSH-06 | `PermitEmptyPasswords` disabled |
| SSH-07 | Protocol 2 only |
| SSH-08 | Non-default port (advisory) |
| SSH-09 | `MaxAuthTries` login attempts ≤ 4 |
| SSH-10 | `LoginGraceTime` ≤ 60s |
| SSH-11 | Access limited (`AllowUsers`/`AllowGroups`/`DenyUsers`) |
| SSH-12 | `X11Forwarding` disabled |
| SSH-13 | `AllowAgentForwarding` disabled |
| SSH-14 | `AllowTcpForwarding` disabled |
| SSH-15 | `PermitTunnel` disabled |
| SSH-16 | `ClientAliveInterval` idle timeout set |
| SSH-17 | No weak KEX/MAC/cipher |
| SSH-18 | `LogLevel` suitable for auth auditing |
| SSH-19 | Root SSH key/directory permissions |
| SSH-20 | Fail2Ban `sshd` jail active |
| SSH-21 | Failed-login count last 24h (brute-force signal) |

Effective values are read with `sshd -T`; `sshd_config` and `sshd_config.d/*.conf` are used as fallback.

### Firewall (`--firewall`)

| ID | Check |
|---|---|
| FW-01 | Firewall active (ufw / firewalld / nftables / iptables) |
| FW-02 | Default inbound policy deny/drop |
| FW-03 | IPv6 policy restrictive |
| FW-04 | SSH not open to the whole internet |
| FW-05 | No DB/cache ports exposed (3306, 5432, 6379, 27017, 9200, 11211, 2375) |
| FW-06 | Listening TCP port inventory |
| FW-07 | Fail2Ban dynamic blocking present |

### Web server (`--web`)

| ID | Check |
|---|---|
| WEB-01/02 | Server running and enabled (nginx/apache/httpd/caddy) |
| WEB-03/04 | Version disclosure off (`server_tokens off`, `ServerTokens Prod`, `ServerSignature Off`) |
| WEB-05 | Directory listing disabled |
| WEB-06 | HTTP to HTTPS redirect |
| WEB-07 | PHP runs under FPM (not mod_php) |
| WEB-08 | `expose_php` off |
| WEB-09 | `display_errors` off |
| WEB-10 | `disable_functions` covers `exec/system/passthru/shell_exec/proc_open/popen` |
| WEB-11 | `open_basedir` set |
| WEB-12 | No world-writable file in webroot |
| WEB-13 | No exposed `.env` / `.git/config` / backup config in webroot |

### TLS/SSL (`--tls`)

| ID | Check |
|---|---|
| TLS-01 | OpenSSL version |
| TLS-02 | SSLv3/TLS1.0/1.1 disabled in config |
| TLS-03 | Certificate expiry (expired / <30 days) |
| TLS-04 | Self-signed certificate detection |
| TLS-05 | Live handshake on `127.0.0.1:443` (protocol/cipher) |
| TLS-06 | HSTS header |
| TLS-07 | Certificate key size ≥ 2048-bit |

### PHP security (`--php`)

| ID | Check |
|---|---|
| PHP-01 | PHP version ≥ 8.4 (EOL below 8) |
| PHP-02 | SAPI is FPM (warns to verify pool ini, not CLI) |
| PHP-03 | `session.upload_progress.enabled=0` (PHP2Shell CVE mitigation) |
| PHP-04 | `cgi.fix_pathinfo=0` |
| PHP-05 | `expose_php=0` |
| PHP-06 | `display_errors=0` |
| PHP-07 | `allow_url_include=0` |
| PHP-08 | `allow_url_fopen` (restrict if unused) |
| PHP-09..13 | Session cookie `httponly`/`secure`/`use_only_cookies`/`use_strict_mode`/`samesite` |
| PHP-14 | `disable_functions` covers `exec/system/passthru/shell_exec/proc_open/popen` |
| PHP-15 | `open_basedir` set |
| PHP-16 | `upload_max_filesize` / `post_max_size` inventory |

Values are read from the FPM `php.ini` when present, otherwise the CLI ini.

### Database hardening (`--db`)

| ID | Check |
|---|---|
| DB-01 | Service running (MySQL/MariaDB/PostgreSQL) |
| DB-02 | Bind address not exposed to all interfaces |
| DB-03 | No remote root account |
| DB-04 | No anonymous accounts |
| DB-05 | No passwordless accounts (non-socket) |
| DB-06 | `local_infile` disabled |
| DB-07 | TLS enforced (`require_secure_transport`) |
| DB-08 | DB config files not world-readable |
| DB-02..05 (PG) | `listen_addresses`, `scram-sha-256`, `ssl`, `pg_hba` trust rules |

MySQL queries run with the local client; without DB credentials the query checks are reported `SKIP`.

### Password policy (`--password`)

| ID | Check |
|---|---|
| PWD-01..04 | `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`, `PASS_WARN_AGE` |
| PWD-05/06 | `pam_pwquality` minlen ≥ 12 and character classes |
| PWD-07 | Account lockout (`pam_faillock`/`pam_tally2`) |
| PWD-08 | Strong hash (yescrypt/sha512, no MD5) |
| PWD-09 | No account with empty password |
| PWD-10 | `/etc/shadow` permissions |
| PWD-11 | root account status |
| PWD-12 | `sudo NOPASSWD` rules |

### System & version (`--system`)

| ID | Check |
|---|---|
| SYS-01 | OS, kernel, uptime |
| SYS-02 | Pending package updates |
| SYS-03 | Automatic security updates |
| SYS-04 | Reboot required |
| SYS-05 | SELinux / AppArmor enforcing |
| SYS-06 | Common sysctl network hardening |
| SYS-07 | IP forwarding |
| SYS-08 | SUID core dumps (`fs.suid_dumpable=0`) |
| SYS-09 | `/tmp` mounted `nosuid,nodev` |
| SYS-10 | NTP time synchronization |
| SYS-11 | `auditd` running |
| SYS-12 | No world-writable directory in `PATH` |
| SYS-13 | `umask` |
| SYS-14 | Listening socket inventory |
| SYS-15 | Cron paths not group/other-writable |
| SYS-16 | No legacy insecure service running (telnet/ftp/rsh/tftp) |

---

## 5. Benchmark Scoring

Each finding carries a severity weight:

| Severity | Weight |
|---|---|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 1 |
| INFO | 0 (not scored) |

`PASS` earns full weight, `WARN` half, `FAIL` zero, `SKIP` is excluded. The weighted percentage maps to a grade:

| Score | Grade |
|---|---|
| ≥ 90 | A |
| ≥ 80 | B |
| ≥ 70 | C |
| ≥ 60 | D |
| < 60 | F |

The summary lists every CRITICAL/HIGH `FAIL` first so remediation can start at the top.

---

## 6. Common Fixes

**Firewall (Ubuntu/Debian)**

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 10.0.0.0/8 to any port 22 proto tcp   # SSH from mgmt only
sudo ufw allow 80,443/tcp
sudo ufw enable
```

**Firewall (RHEL family)**

```bash
sudo dnf install -y firewalld
sudo systemctl enable --now firewalld
sudo firewall-cmd --permanent --add-service=http --add-service=https
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.0.0.0/8 service name=ssh accept'
sudo firewall-cmd --reload
```

**SSH hardening (drop-in, keeps defaults intact)**

```bash
sudo tee /etc/ssh/sshd_config.d/99-hardening.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
EOF
sudo sshd -t && sudo systemctl reload ssh
```

**Fail2Ban**

```bash
sudo apt install -y fail2ban        # or: sudo dnf install -y fail2ban
sudo tee /etc/fail2ban/jail.local >/dev/null <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
EOF
sudo systemctl enable --now fail2ban
```

**PHP (FPM) security**

```bash
sudo tee /etc/php/8.4/fpm/conf.d/99-security.ini >/dev/null <<'EOF'
session.upload_progress.enabled = Off
cgi.fix_pathinfo = 0
expose_php = Off
display_errors = Off
log_errors = On
allow_url_include = Off
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_only_cookies = 1
session.use_strict_mode = 1
session.cookie_samesite = "Lax"
open_basedir = /var/www/html:/tmp
disable_functions = exec,system,passthru,shell_exec,proc_open,popen
EOF
sudo systemctl reload php8.4-fpm
```

Verify per pool with `php-fpm8.4 -tt` and a `phpinfo()`/CLI check. `disable_functions` can break legacy applications — remove only the functions the app does not use.

**Database**

MySQL/MariaDB:

```bash
sudo tee /etc/mysql/mysql.conf.d/99-hardening.cnf >/dev/null <<'EOF'
[mysqld]
bind-address = 127.0.0.1
local_infile = 0
require_secure_transport = ON
EOF
sudo systemctl restart mysql
```

Then remove anonymous and remote-root accounts:

```sql
DROP USER IF EXISTS ''@'localhost';
DELETE FROM mysql.user WHERE user='';
DELETE FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1');
FLUSH PRIVILEGES;
```

PostgreSQL:

```conf
# postgresql.conf
listen_addresses = 'localhost'
password_encryption = scram-sha-256
ssl = on
```

Use `scram-sha-256` (not `trust`/`md5`) in `pg_hba.conf` for every non-local line.

**Password policy**

```bash
sudo tee /etc/security/pwquality.conf >/dev/null <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
# Lockout
sudo tee /etc/security/faillock.conf >/dev/null <<'EOF'
deny = 5
unlock_time = 900
EOF
```

**TLS protocols (nginx)**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Sysctl network hardening**

```bash
sudo tee /etc/sysctl.d/99-hardening.conf >/dev/null <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF
sudo sysctl --system
```

**Automatic security updates (Ubuntu)**

```bash
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## 7. Multi-Distro Notes

| Concern | Behavior |
|---|---|
| Package manager | Auto-detects `apt-get`, `dnf`, `yum`, `zypper`, `pacman`, `apk` |
| Firewall | Detects whichever of ufw/firewalld/nftables/iptables is present |
| Web server | nginx, apache2, httpd, caddy |
| Web config path | `/etc/nginx`, `/etc/apache2`, `/etc/httpd`, `/etc/caddy` |
| Service control | `systemctl` when available |
| SELinux vs AppArmor | Both probed; at least one must be enforcing |
| Unknown tooling | Reported as `SKIP`/`INFO`, never as a failure |

---

## 8. Workflow for This Migration

1. On each old **CentOS** server, run `sudo bash hardening-check.sh --benchmark --json > baseline-centos.json` and keep it.
2. After the Ubuntu 26.04 server is configured, run `sudo bash hardening-check.sh --benchmark --json > baseline-ubuntu.json`.
3. Compare the two reports to prove the improvement and catch regressions:
   ```bash
   sudo bash hardening-check.sh --benchmark --diff baseline-centos.json
   ```
4. No non-accepted CRITICAL/HIGH `FAIL` may remain before go-live. Waive documented risks explicitly:
   ```bash
   sudo bash hardening-check.sh --benchmark --accept SSH-03,SSH-08
   ```
5. Re-run `--quick` after each remediation batch until the exit code is `0`.
6. Attach all reports to the maintenance berita acara.

---

## 9. Safety

- Read-only. The script changes nothing; it only reads configuration and status.
- Some scans (`find` in webroot, certificate parsing, update check) are bounded and can be skipped with `--quick`.
- Run with `--report` on a path writable by the executing user if `tools/result` is not available.
