#!/usr/bin/env bash
#
# hardening-check.sh
# Security hardening assessment & benchmark for Linux servers.
# Cross-distro: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, Fedora, SUSE, Arch.
#
# Usage:
#   sudo bash hardening-check.sh                 # Run all checks
#   sudo bash hardening-check.sh --ssh           # SSH only
#   sudo bash hardening-check.sh --firewall      # Firewall only
#   sudo bash hardening-check.sh --web           # Web server only
#   sudo bash hardening-check.sh --tls           # TLS/SSL only
#   sudo bash hardening-check.sh --password      # Password policy only
#   sudo bash hardening-check.sh --system        # System/kernel only
#   sudo bash hardening-check.sh --quick         # Skip slow checks (updates, logs, cert scan)
#   sudo bash hardening-check.sh --benchmark     # All checks + grade summary
#   sudo bash hardening-check.sh --json          # Machine-readable output
#   sudo bash hardening-check.sh --report FILE   # Custom report path
#   sudo bash hardening-check.sh --self-test     # Test helpers, touch nothing
#
# Exit codes:
#   0 = no HIGH/CRITICAL failures
#   1 = at least one HIGH/CRITICAL failure
#   2 = usage error / missing dependency

set -u

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESULT_DIR="$(dirname "$SELF_DIR")/result"
HOSTNAME_S=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)
REPORT="${RESULT_DIR}/hardening-${HOSTNAME_S}-$(date +%Y%m%d-%H%M%S).log"

# ---------- Options ----------
RUN_SSH=0; RUN_FW=0; RUN_WEB=0; RUN_TLS=0; RUN_PWD=0; RUN_SYS=0; RUN_PHP=0; RUN_DB=0
QUICK=0; JSON=0; BENCH=0; FORCE_COLOR=0; REPORT_SET=0; DIFF_FILE=""; ACCEPT=","

usage() {
  cat <<'EOF'
Usage: sudo bash hardening-check.sh [options]

  --ssh           SSH hardening checks
  --firewall      Firewall checks
  --web           Web server checks
  --tls           TLS/SSL checks
  --password      Password policy checks
  --php           PHP security checks (FPM/CLI ini)
  --db            Database hardening checks (MySQL/MariaDB/PostgreSQL)
  --system        System/kernel/version checks
  --all           Run every section (default)
  --benchmark     Run every section and show grade
  --quick         Skip slow checks (updates, logs, cert scan, webroot scan)
  --json          Machine-readable JSON output
  --report FILE   Custom report path
  --diff FILE     Compare against a previous --json report
  --accept IDS    Comma-separated IDs treated as accepted risk (e.g. SSH-03,SSH-08)
  --color         Force colors when piped
  --self-test     Test helpers, touch nothing
  --help, -h      This help
EOF
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ssh)        RUN_SSH=1 ;;
    --firewall)   RUN_FW=1 ;;
    --web)        RUN_WEB=1 ;;
    --tls)        RUN_TLS=1 ;;
    --password)   RUN_PWD=1 ;;
    --php)        RUN_PHP=1 ;;
    --db)         RUN_DB=1 ;;
    --system)     RUN_SYS=1 ;;
    --all)        RUN_SSH=1; RUN_FW=1; RUN_WEB=1; RUN_TLS=1; RUN_PWD=1; RUN_SYS=1; RUN_PHP=1; RUN_DB=1 ;;
    --quick)      QUICK=1 ;;
    --json)       JSON=1 ;;
    --benchmark)  BENCH=1; RUN_SSH=1; RUN_FW=1; RUN_WEB=1; RUN_TLS=1; RUN_PWD=1; RUN_SYS=1; RUN_PHP=1; RUN_DB=1 ;;
    --diff)       DIFF_FILE="${2:-}"; [ -z "$DIFF_FILE" ] && { echo "Missing value for --diff" >&2; exit 2; }; shift ;;
    --accept)     ACCEPT="${2:-}"; [ -z "$ACCEPT" ] && { echo "Missing value for --accept" >&2; exit 2; }; shift ;;
    --report)     REPORT="${2:-}"; [ -z "$REPORT" ] && { echo "Missing value for --report" >&2; exit 2; }; REPORT_SET=1; shift ;;
    --color)      FORCE_COLOR=1 ;;
    --help|-h)    usage ;;
    --self-test)  SELF_TEST=1 ;;
    *) echo "Unknown option: $1" >&2; echo "Try --help" >&2; exit 2 ;;
  esac
  shift
done

if [ "${SELF_TEST:-0}" -eq 0 ] && [ $RUN_SSH -eq 0 ] && [ $RUN_FW -eq 0 ] && [ $RUN_WEB -eq 0 ] \
   && [ $RUN_TLS -eq 0 ] && [ $RUN_PWD -eq 0 ] && [ $RUN_SYS -eq 0 ] \
   && [ $RUN_PHP -eq 0 ] && [ $RUN_DB -eq 0 ]; then
  RUN_SSH=1; RUN_FW=1; RUN_WEB=1; RUN_TLS=1; RUN_PWD=1; RUN_SYS=1; RUN_PHP=1; RUN_DB=1
fi

# ---------- Colors ----------
if [ -t 1 ] || [ $FORCE_COLOR -eq 1 ]; then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; C=$'\e[36m'; N=$'\e[0m'
else
  G=''; R=''; Y=''; B=''; C=''; N=''
fi

# ---------- Result store ----------
F_ID=(); F_SEV=(); F_STAT=(); F_MSG=(); F_SECTION=()
TOTAL=0; N_PASS=0; N_WARN=0; N_FAIL=0; N_SKIP=0; N_INFO=0
W_PASS=0; W_TOTAL=0
CUR_SECTION=""

section() {
  CUR_SECTION="$1"
  [ $JSON -eq 1 ] && return
  echo
  echo "${B}== $1 ==${N}"
}

# check <id> <severity> <status> <message>
# status: PASS | WARN | FAIL | INFO | SKIP
check() {
  local id=$1 sev=$2 stat=$3 msg=$4
  F_ID+=("$id"); F_SEV+=("$sev"); F_STAT+=("$stat"); F_MSG+=("$msg"); F_SECTION+=("$CUR_SECTION")
  TOTAL=$((TOTAL+1))
  local w=0
  case "$sev" in
    CRITICAL) w=10 ;;
    HIGH)     w=7 ;;
    MEDIUM)   w=4 ;;
    LOW)      w=1 ;;
    INFO)     w=0 ;;
  esac
  case "$stat" in
    PASS) N_PASS=$((N_PASS+1)); W_PASS=$((W_PASS+w)); W_TOTAL=$((W_TOTAL+w)) ;;
    WARN) N_WARN=$((N_WARN+1)); W_PASS=$((W_PASS+w/2)); W_TOTAL=$((W_TOTAL+w)) ;;
    FAIL) N_FAIL=$((N_FAIL+1)); W_TOTAL=$((W_TOTAL+w)) ;;
    SKIP) N_SKIP=$((N_SKIP+1)) ;;
    INFO) N_INFO=$((N_INFO+1)) ;;
  esac
  [ $JSON -eq 1 ] && return
  local tag
  case "$stat" in
    PASS) tag="${G}[PASS]${N}" ;;
    WARN) tag="${Y}[WARN]${N}" ;;
    FAIL) tag="${R}[FAIL]${N}" ;;
    SKIP) tag="${C}[SKIP]${N}" ;;
    *)    tag="${C}[INFO]${N}" ;;
  esac
  printf '  %s %-9s %-8s %s\n' "$tag" "$id" "$sev" "$msg"
}

# ---------- Helpers ----------
# Escape a value for embedding in a JSON string literal (bash builtins only).
json_esc() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u)" -eq 0 ]; }
# timeout wrapper (GNU timeout; plain run if absent)
tmo() { local s=$1; shift; if have timeout; then timeout "$s" "$@"; else "$@"; fi; }
read_os() {
  OS_ID=""; OS_VER=""; OS_NAME=""; OS_LIKE=""
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"; OS_LIKE="${ID_LIKE:-}"
  fi
}
pkg_manager() {
  for p in apt-get dnf yum zypper pacman apk; do have "$p" && { echo "$p"; return; }; done
  echo ""
}
webver() {
  case "$1" in
    nginx)   nginx -v 2>&1 | head -1 ;;
    apache2|httpd) "$1" -v 2>&1 | head -1 ;;
    caddy)   caddy version 2>&1 | head -1 ;;
    *)       echo "$1" ;;
  esac
}
# sshd_get <Keyword> -> effective value, lowercased key match, first hit
sshd_get() {
  local key=$1 val=""
  if is_root && have sshd; then
    val=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==tolower(k) {print $2; exit}')
    [ -n "$val" ] && { echo "$val"; return; }
  fi
  {
    [ -r /etc/ssh/sshd_config ] && cat /etc/ssh/sshd_config
    if [ -d /etc/ssh/sshd_config.d ]; then
      for f in /etc/ssh/sshd_config.d/*.conf; do [ -r "$f" ] && cat "$f"; done
    fi
  } 2>/dev/null | awk -v k="$key" \
      'tolower($1)=="match" {exit} tolower($1)==tolower(k) {v=$2} END {print v}'
}
svc_active() {
  local s=$1
  if have systemctl; then systemctl is-active "$s" >/dev/null 2>&1 && return 0 || return 1; fi
  if have service; then service "$s" status >/dev/null 2>&1; return $?; fi
  return 1
}
svc_enabled() {
  local s=$1
  have systemctl || return 1
  systemctl is-enabled "$s" >/dev/null 2>&1
}
port_listening() {
  local p=$1
  if have ss; then ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"; return $?; fi
  if have netstat; then netstat -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"; return $?; fi
  return 1
}
num_lt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}'; }
num_gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 > b+0)}'; }
is_num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# Accepted-risk whitelist (IDs in comma list)
is_accepted() { case ",$ACCEPT," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# PHP ini value from the FPM ini when available, else CLI ini.
php_ini_get() {
  local key=$1 ini="" v
  if have php; then
    for f in /etc/php/*/fpm/php.ini /etc/php.ini; do
      [ -r "$f" ] && { ini=$f; break; }
    done
    if [ -n "$ini" ]; then
      v=$(php -c "$ini" -r "echo ini_get('$key');" 2>/dev/null)
    else
      v=$(php -r "echo ini_get('$key');" 2>/dev/null)
    fi
    echo "${v:-}"
  fi
}

# PHP boolean ini as 1/0 ("" and "0" count as off).
php_ini_bool() {
  local key=$1 ini="" v
  if have php; then
    for f in /etc/php/*/fpm/php.ini /etc/php.ini; do
      [ -r "$f" ] && { ini=$f; break; }
    done
    if [ -n "$ini" ]; then
      v=$(php -c "$ini" -r "echo ((bool)ini_get('$key'))?'1':'0';" 2>/dev/null)
    else
      v=$(php -r "echo ((bool)ini_get('$key'))?'1':'0';" 2>/dev/null)
    fi
    echo "${v:-0}"
  else
    echo "0"
  fi
}

# ---------- Self-test (no system access) ----------
self_test() {
  local fail=0
  _t() { [ "$1" = "$2" ] && echo "ok   $3" || { echo "FAIL $3 (got '$1', want '$2')"; fail=1; }; }
  _t "$(num_lt 5 10 && echo y)" "y" "num_lt 5<10"
  _t "$(num_gt 5 10 && echo y)" "" "num_gt 5>10 false"
  _t "$(is_num 42 && echo y)" "y" "is_num 42"
  _t "$(is_num abc && echo y)" "" "is_num abc false"
  # grade thresholds
  _t "$(grade_for 95)" "A" "grade 95=A"
  _t "$(grade_for 85)" "B" "grade 85=B"
  _t "$(grade_for 75)" "C" "grade 75=C"
  _t "$(grade_for 65)" "D" "grade 65=D"
  _t "$(grade_for 30)" "F" "grade 30=F"
  _t "$(score_and_grade 0 0)" "N/A N/A" "all skipped is N/A, not F"
  echo
  [ $fail -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
  return $fail
}
grade_for() {
  local s=$1
  if num_gt "$s" 89; then echo A
  elif num_gt "$s" 79; then echo B
  elif num_gt "$s" 69; then echo C
  elif num_gt "$s" 59; then echo D
  else echo F; fi
}

# "<score> <grade>", or "N/A N/A" when every check was skipped.
score_and_grade() {
  local p=$1 t=$2
  if [ "$t" -le 0 ]; then echo "N/A N/A"; return; fi
  local s
  s=$(awk -v p="$p" -v t="$t" 'BEGIN{printf "%.1f", p*100/t}')
  echo "$s $(grade_for "$s")"
}

if [ "${SELF_TEST:-0}" -eq 1 ]; then self_test; exit $?; fi

read_os
PKG=$(pkg_manager)

# ---------- Report header ----------
mkdir -p "$RESULT_DIR" 2>/dev/null || true
[ $REPORT_SET -eq 1 ] && mkdir -p "$(dirname "$REPORT")" 2>/dev/null || true
{
  echo "Hardening Assessment Report"
  echo "Host      : $HOSTNAME_S"
  echo "Date      : $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "OS        : ${OS_NAME:-unknown}"
  echo "Kernel    : $(uname -srm 2>/dev/null)"
  echo "Package   : ${PKG:-unknown}"
  echo "Root      : $(is_root && echo yes || echo no)"
  echo "Mode      : $([ $QUICK -eq 1 ] && echo quick || echo full)"
  echo
} > "$REPORT" 2>/dev/null || true

# Log every human line to the report as well.
if [ $JSON -eq 0 ]; then
  echo "${B}HARDENING ASSESSMENT${N}"
  echo "Host   : $HOSTNAME_S"
  echo "OS     : ${OS_NAME:-unknown}  (kernel $(uname -r 2>/dev/null))"
  echo "Report : $REPORT"
  echo "Mode   : $([ $QUICK -eq 1 ] && echo 'quick' || echo 'full')"
fi

# ============================================================
# SSH HARDENING
# ============================================================
check_ssh() {
  section "SSH HARDENING"

  if [ ! -r /etc/ssh/sshd_config ]; then
    check SSH-00 MEDIUM SKIP "sshd_config not found (OpenSSH server not installed?)"
    return
  fi

  svc_active sshd || svc_active ssh \
    && check SSH-01 HIGH PASS "SSH service is running" \
    || check SSH-01 HIGH FAIL "SSH service is not running"

  svc_enabled sshd || svc_enabled ssh \
    && check SSH-02 MEDIUM PASS "SSH service enabled at boot" \
    || check SSH-02 MEDIUM WARN "SSH service not enabled at boot"

  # Direct root login
  local rl; rl=$(sshd_get PermitRootLogin); rl=${rl:-prohibit-password}
  case "$rl" in
    no) check SSH-03 HIGH PASS "PermitRootLogin = no" ;;
    prohibit-password|without-password) check SSH-03 HIGH WARN "PermitRootLogin = $rl (key-only root; prefer 'no' + sudo user)" ;;
    *) check SSH-03 CRITICAL FAIL "PermitRootLogin = $rl (direct root login allowed)" ;;
  esac

  # Key authentication
  local pa pk; pa=$(sshd_get PasswordAuthentication); pk=$(sshd_get PubkeyAuthentication)
  pa=${pa:-yes}; pk=${pk:-yes}
  [ "$pk" = "yes" ] && check SSH-04 HIGH PASS "PubkeyAuthentication enabled" \
                     || check SSH-04 HIGH FAIL "PubkeyAuthentication disabled"
  [ "$pa" = "no" ] && check SSH-05 HIGH PASS "PasswordAuthentication disabled" \
                   || check SSH-05 HIGH FAIL "PasswordAuthentication = $pa (brute-force risk)"

  # Empty passwords
  local ep; ep=$(sshd_get PermitEmptyPasswords); ep=${ep:-no}
  [ "$ep" = "no" ] && check SSH-06 CRITICAL PASS "PermitEmptyPasswords disabled" \
                   || check SSH-06 CRITICAL FAIL "PermitEmptyPasswords enabled"

  # Protocol
  local proto; proto=$(sshd_get Protocol)
  if [ -z "$proto" ] || [ "$proto" = "2" ]; then
    check SSH-07 MEDIUM PASS "SSH protocol 2 only (modern OpenSSH default)"
  else
    check SSH-07 CRITICAL FAIL "Protocol = $proto (protocol 1 is insecure)"
  fi

  # Port
  local port; port=$(sshd_get Port); port=${port:-22}
  if [ "$port" = "22" ]; then
    check SSH-08 LOW INFO "SSH port = 22 (default; non-default port reduces noise, not risk)"
  else
    check SSH-08 LOW PASS "SSH port = $port (non-default)"
  fi

  # Login attempts / grace
  local mat; mat=$(sshd_get MaxAuthTries); mat=${mat:-6}
  is_num "$mat" && [ "$mat" -le 4 ] \
    && check SSH-09 MEDIUM PASS "MaxAuthTries = $mat" \
    || check SSH-09 MEDIUM WARN "MaxAuthTries = $mat (recommend <= 4)"
  local lg; lg=$(sshd_get LoginGraceTime); lg=${lg:-120}
  is_num "$lg" && [ "$lg" -le 60 ] \
    && check SSH-10 LOW PASS "LoginGraceTime = ${lg}s" \
    || check SSH-10 LOW WARN "LoginGraceTime = ${lg}s (recommend <= 60)"

  # Access limiting
  local au ag du dg; au=$(sshd_get AllowUsers); ag=$(sshd_get AllowGroups)
  du=$(sshd_get DenyUsers); dg=$(sshd_get DenyGroups)
  if [ -n "$au" ] || [ -n "$ag" ]; then
    check SSH-11 MEDIUM PASS "SSH access restricted (${au:+AllowUsers=$au }${ag:+AllowGroups=$ag})"
  elif [ -n "$du" ] || [ -n "$dg" ]; then
    check SSH-11 MEDIUM PASS "SSH access restricted (${du:+DenyUsers=$du }${dg:+DenyGroups=$dg})"
  else
    check SSH-11 MEDIUM WARN "No Allow/Deny list (consider AllowUsers/AllowGroups)"
  fi

  # Unnecessary features
  local x11 ac af pt
  x11=$(sshd_get X11Forwarding); x11=${x11:-no}
  ac=$(sshd_get AllowAgentForwarding); ac=${ac:-no}
  af=$(sshd_get AllowTcpForwarding); af=${af:-yes}
  pt=$(sshd_get PermitTunnel); pt=${pt:-no}
  [ "$x11" = "no" ] && check SSH-12 LOW PASS "X11Forwarding disabled" \
                    || check SSH-12 LOW WARN "X11Forwarding enabled"
  [ "$ac" = "no" ] && check SSH-13 LOW PASS "AllowAgentForwarding disabled" \
                   || check SSH-13 LOW WARN "AllowAgentForwarding enabled"
  [ "$af" = "no" ] && check SSH-14 MEDIUM PASS "AllowTcpForwarding disabled" \
                   || check SSH-14 MEDIUM WARN "AllowTcpForwarding = $af"
  [ "$pt" = "no" ] && check SSH-15 MEDIUM PASS "PermitTunnel disabled" \
                   || check SSH-15 MEDIUM FAIL "PermitTunnel enabled"

  # Client alive
  local cai cmc; cai=$(sshd_get ClientAliveInterval); cmc=$(sshd_get ClientAliveCountMax)
  cai=${cai:-0}
  if is_num "$cai" && [ "$cai" -gt 0 ]; then
    check SSH-16 LOW PASS "ClientAliveInterval = ${cai}s (${cmc:-0} max)"
  else
    check SSH-16 LOW WARN "ClientAliveInterval not set (idle sessions never expire)"
  fi

  # Weak crypto
  local kex macs ciphers weak=""
  kex=$(sshd_get KexAlgorithms); macs=$(sshd_get MACs); ciphers=$(sshd_get Ciphers)
  for pat in diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 3des-cbc blowfish-cbc arcfour; do
    echo "$kex $macs $ciphers" | grep -q "$pat" && weak="$weak $pat"
  done
  [ -z "$weak" ] && check SSH-17 HIGH PASS "No known weak KEX/MAC/cipher in config" \
                 || check SSH-17 HIGH FAIL "Weak crypto configured:$weak"

  # Log level
  local ll; ll=$(sshd_get LogLevel); ll=${ll:-INFO}
  case "$ll" in
    VERBOSE|DEBUG|DEBUG1|DEBUG2|DEBUG3) check SSH-18 LOW PASS "LogLevel = $ll" ;;
    INFO) check SSH-18 LOW WARN "LogLevel = INFO (VERBOSE logs auth failures with detail)" ;;
    *) check SSH-18 LOW WARN "LogLevel = $ll" ;;
  esac

  # Key file permissions
  local kbad=0
  if [ -d /root/.ssh ]; then
    local m; m=$(stat -c '%a' /root/.ssh 2>/dev/null || stat -f '%Lp' /root/.ssh 2>/dev/null)
    [ "$m" = "700" ] || kbad=$((kbad+1))
  fi
  for f in /root/.ssh/authorized_keys /root/.ssh/*.pub; do
    [ -e "$f" ] || continue
    local m; m=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)
    [ "$m" = "600" ] || [ "$m" = "644" ] || kbad=$((kbad+1))
  done
  [ $kbad -eq 0 ] && check SSH-19 MEDIUM PASS "Root SSH key/dir permissions OK" \
                  || check SSH-19 MEDIUM FAIL "$kbad root SSH key path(s) with loose permissions"

  # Fail2Ban for SSH
  if have fail2ban-client; then
    if fail2ban-client status sshd >/dev/null 2>&1; then
      local j; j=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/ /,"",$2); print $2}')
      check SSH-20 HIGH PASS "Fail2Ban sshd jail active (banned: ${j:-?})"
    else
      check SSH-20 HIGH WARN "Fail2Ban installed but no sshd jail active"
    fi
  else
    check SSH-20 HIGH WARN "Fail2Ban not installed (no brute-force auto-ban)"
  fi

  # Auth log monitoring
  local fails=""
  if have journalctl; then
    fails=$(journalctl -u ssh -u sshd --since '-24 hours' 2>/dev/null | grep -c 'Failed password')
  elif [ -r /var/log/auth.log ]; then
    fails=$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null)
  elif [ -r /var/log/secure ]; then
    fails=$(grep -c 'Failed password' /var/log/secure 2>/dev/null)
  fi
  if [ -n "$fails" ]; then
    num_gt "$fails" 50 \
      && check SSH-21 HIGH WARN "SSH failed logins last 24h: $fails (possible brute force)" \
      || check SSH-21 LOW PASS "SSH failed logins last 24h: $fails"
  else
    check SSH-21 LOW INFO "SSH auth log unavailable (journald/rsyslog?)"
  fi
}

# ============================================================
# FIREWALL
# ============================================================
check_firewall() {
  section "FIREWALL"

  local engine="" active=0
  if have ufw; then engine=ufw; ufw status 2>/dev/null | grep -qi 'Status: active' && active=1
  elif have firewall-cmd; then engine=firewalld; firewall-cmd --state 2>/dev/null | grep -q running && active=1
  elif have nft; then engine=nftables; nft list ruleset 2>/dev/null | grep -q 'table' && active=1
  elif have iptables; then engine=iptables; iptables -S 2>/dev/null | grep -qv '^-P' && active=1
  fi

  if [ -z "$engine" ]; then
    check FW-01 CRITICAL FAIL "No firewall tooling found (ufw/firewalld/nftables/iptables)"
    return
  fi

  [ $active -eq 1 ] && check FW-01 CRITICAL PASS "Firewall active ($engine)" \
                    || check FW-01 CRITICAL FAIL "Firewall present but NOT active ($engine)"

  local deny=0 open_any=""
  case "$engine" in
    ufw)
      ufw status verbose 2>/dev/null | grep -qi 'Default: deny (incoming)' && deny=1
      open_any=$(ufw status 2>/dev/null | awk '/ALLOW/ && /Anywhere/ {print $1}' | sort -u | tr '\n' ' ')
      ;;
    firewalld)
      local dp; dp=$(firewall-cmd --get-default-zone 2>/dev/null)
      firewall-cmd --zone="$dp" --query-target 2>/dev/null | grep -q DROP && deny=1
      firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+/' | cut -d/ -f1 > /tmp/fw.ports.$$
      open_any=$(tr '\n' ' ' < /tmp/fw.ports.$$ 2>/dev/null); rm -f /tmp/fw.ports.$$
      ;;
    nftables)
      nft list ruleset 2>/dev/null | grep -qE 'hook input' && deny=1
      ;;
    iptables)
      iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT DROP' && deny=1
      ;;
  esac

  [ $deny -eq 1 ] && check FW-02 HIGH PASS "Default inbound policy = deny/drop" \
                  || check FW-02 HIGH WARN "Default inbound policy does not deny"

  # IPv6
  local v6=0
  if have ip6tables && ip6tables -S 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then v6=1; fi
  if [ "$engine" = "ufw" ] && ufw status 2>/dev/null | grep -qi 'v6'; then v6=1; fi
  [ $v6 -eq 1 ] && check FW-03 MEDIUM PASS "IPv6 inbound policy also restrictive" \
                || check FW-03 MEDIUM WARN "IPv6 inbound policy not confirmed"

  # SSH exposure
  case "$engine" in
    ufw)
      ufw status 2>/dev/null | grep -E '^22| 22' | grep -qi 'Anywhere' \
        && check FW-04 MEDIUM WARN "SSH (22) open to Anywhere" \
        || check FW-04 MEDIUM PASS "SSH not open to Anywhere" ;;
    firewalld)
      firewall-cmd --list-services 2>/dev/null | grep -qw ssh \
        && check FW-04 MEDIUM WARN "SSH service allowed in default zone" \
        || check FW-04 MEDIUM PASS "SSH not opened via firewalld service" ;;
    *) check FW-04 LOW INFO "SSH exposure check only for ufw/firewalld" ;;
  esac

  # Dangerous DB/queue ports
  local danger=""
  for p in 3306 5432 6379 27017 9200 11211 2375; do
    if echo "$open_any" | grep -qw "$p"; then danger="$danger $p"; fi
  done
  if [ -n "$danger" ]; then
    check FW-05 CRITICAL FAIL "Sensitive port(s) open to any:$danger (3306/5432/6379/27017/9200/11211/2375)"
  else
    check FW-05 HIGH PASS "No obvious sensitive DB/cache port open to any"
  fi

  # Open port summary
  local ports
  ports=$( { ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null; } | awk 'NR>1{print $4}' | sed 's/.*[:.]//' | sort -un | tr '\n' ' ')
  check FW-06 LOW INFO "Listening TCP ports: ${ports:-none}"

  # fail2ban as firewall layer
  if have fail2ban-client; then
    check FW-07 MEDIUM PASS "Fail2Ban present (dynamic blocking)"
  else
    check FW-07 MEDIUM WARN "Fail2Ban absent (no dynamic blocking)"
  fi
}

# ============================================================
# WEB SERVER
# ============================================================
check_web() {
  section "WEB SERVER"

  local web=""
  svc_active nginx && web=nginx
  [ -z "$web" ] && { svc_active apache2 && web=apache2; }
  [ -z "$web" ] && { svc_active httpd && web=httpd; }
  [ -z "$web" ] && { svc_active caddy && web=caddy; }

  if [ -z "$web" ]; then
    check WEB-01 LOW SKIP "No web server running (nginx/apache2/httpd/caddy)"
    return
  fi
  check WEB-01 MEDIUM PASS "Web server running: $web ($(webver "$web"))"
  svc_enabled "$web" && check WEB-02 LOW PASS "$web enabled at boot" \
                     || check WEB-02 LOW WARN "$web not enabled at boot"

  local confdir=""
  case "$web" in
    nginx)   confdir=/etc/nginx ;;
    apache2) confdir=/etc/apache2 ;;
    httpd)   confdir=/etc/httpd ;;
    caddy)   confdir=/etc/caddy ;;
  esac

  # Version disclosure
  if [ "$web" = "nginx" ]; then
    grep -rqsE 'server_tokens[[:space:]]+off' "$confdir" 2>/dev/null \
      && check WEB-03 MEDIUM PASS "nginx server_tokens off" \
      || check WEB-03 MEDIUM WARN "nginx server_tokens not disabled (version leaked)"
  else
    local st ss
    st=$(grep -rhi '^\s*ServerTokens' "$confdir" 2>/dev/null | awk '{print $2}' | tail -1)
    ss=$(grep -rhi '^\s*ServerSignature' "$confdir" 2>/dev/null | awk '{print $2}' | tail -1)
    [ "${st:-Full}" = "Prod" ] && check WEB-03 MEDIUM PASS "Apache ServerTokens Prod" \
                               || check WEB-03 MEDIUM WARN "Apache ServerTokens = ${st:-Full}"
    [ "${ss:-On}" = "Off" ] && check WEB-04 LOW PASS "Apache ServerSignature Off" \
                            || check WEB-04 LOW WARN "Apache ServerSignature = ${ss:-On}"
  fi

  # Directory listing
  if [ "$web" = "nginx" ]; then
    if grep -rqsE 'autoindex\s+on' "$confdir" 2>/dev/null; then
      check WEB-05 MEDIUM FAIL "nginx autoindex ON (directory listing)"
    else
      check WEB-05 MEDIUM PASS "nginx autoindex off"
    fi
  else
    if grep -rqsE '^\s*Options\s+.*Indexes' "$confdir" 2>/dev/null; then
      check WEB-05 MEDIUM FAIL "Apache Options +Indexes (directory listing)"
    else
      check WEB-05 MEDIUM PASS "Apache directory listing disabled"
    fi
  fi

  # HTTP -> HTTPS redirect
  if grep -rqsE 'return\s+301\s+https|RewriteRule.*https' "$confdir" 2>/dev/null; then
    check WEB-06 HIGH PASS "HTTP to HTTPS redirect present"
  else
    check WEB-06 HIGH WARN "No HTTP->HTTPS redirect found in config"
  fi

  # PHP SAPI
  if have php; then
    local sapi; sapi=$(php -r 'echo PHP_SAPI;' 2>/dev/null)
    if [ "$sapi" = "fpm-fcgi" ]; then
      check WEB-07 HIGH PASS "PHP runs as FPM (fpm-fcgi)"
    elif [ "$sapi" = "cli" ]; then
      check WEB-07 LOW INFO "PHP CLI detected; web SAPI checked via FPM service"
    else
      check WEB-07 HIGH WARN "PHP SAPI = $sapi (mod_php discouraged)"
    fi

    local ep; ep=$(php -r 'echo ini_get("expose_php");' 2>/dev/null)
    [ "$ep" = "0" ] || [ "$ep" = "" ] && check WEB-08 MEDIUM PASS "PHP expose_php off" \
                                     || check WEB-08 MEDIUM WARN "PHP expose_php on (version leaked)"

    local de; de=$(php -r 'echo ini_get("display_errors");' 2>/dev/null)
    [ "$de" = "0" ] || [ "$de" = "" ] && check WEB-09 HIGH PASS "PHP display_errors off" \
                                     || check WEB-09 HIGH FAIL "PHP display_errors on (info leak)"

    local df; df=$(php -r 'echo ini_get("disable_functions");' 2>/dev/null)
    local need="exec system passthru shell_exec proc_open popen"
    local missing=""
    for fn in $need; do echo "$df" | grep -qw "$fn" || missing="$missing $fn"; done
    [ -z "$missing" ] && check WEB-10 MEDIUM PASS "PHP disable_functions covers dangerous calls" \
                      || check WEB-10 MEDIUM WARN "PHP disable_functions missing:$missing"

    local ob; ob=$(php -r 'echo ini_get("open_basedir");' 2>/dev/null)
    [ -n "$ob" ] && check WEB-11 MEDIUM PASS "PHP open_basedir set ($ob)" \
                 || check WEB-11 MEDIUM WARN "PHP open_basedir not set"
  else
    check WEB-07 LOW SKIP "PHP not installed"
  fi

  # Webroot writability + secrets exposure
  local roots="/var/www /var/www/html /usr/share/nginx/html"
  if [ $QUICK -eq 1 ]; then
    check WEB-12 MEDIUM SKIP "Webroot world-writable scan skipped (--quick)"
  else
    local bad=0 scanned=0
    for r in $roots; do
      [ -d "$r" ] || continue
      scanned=$((scanned+1))
      local w; w=$(tmo 60 find "$r" -maxdepth 3 -type f -perm -0002 2>/dev/null | head -5)
      [ -n "$w" ] && bad=$((bad+1))
    done
    if [ $scanned -gt 0 ]; then
      [ $bad -eq 0 ] && check WEB-12 MEDIUM PASS "Webroot has no world-writable files (depth 3)" \
                     || check WEB-12 MEDIUM FAIL "World-writable file(s) in webroot"
    else
      check WEB-12 LOW SKIP "No standard webroot found"
    fi
  fi

  # Exposed secrets
  local leaks=""
  for r in $roots; do
    [ -d "$r" ] || continue
    for f in "$r/.env" "$r/.git/config" "$r/config.php.bak" "$r/wp-config.php.bak"; do
      [ -e "$f" ] && leaks="$leaks $(basename "$f")"
    done
  done
  [ -z "$leaks" ] && check WEB-13 HIGH PASS "No obvious exposed secret/config artifact in webroot" \
                  || check WEB-13 CRITICAL FAIL "Exposed sensitive file(s):$leaks"
}

# ============================================================
# TLS / SSL
# ============================================================
check_tls() {
  section "TLS / SSL"

  if ! have openssl; then
    check TLS-01 HIGH FAIL "openssl not found (cannot assess TLS)"
    return
  fi
  check TLS-01 LOW INFO "OpenSSL $(openssl version 2>/dev/null | awk '{print $2}')"

  # Config-declared protocols
  local proto_conf=""
  if [ -d /etc/nginx ]; then
    proto_conf=$(grep -rhsE '^\s*ssl_protocols' /etc/nginx 2>/dev/null | tail -1)
  fi
  if [ -d /etc/apache2 ] || [ -d /etc/httpd ]; then
    local ap; ap=$(grep -rhsiE '^\s*SSLProtocol' /etc/apache2 /etc/httpd 2>/dev/null | tail -1)
    [ -n "$ap" ] && proto_conf="$proto_conf $ap"
  fi

  if [ -n "$proto_conf" ]; then
    if echo "$proto_conf" | grep -qi 'ssl_protocols'; then
      if echo "$proto_conf" | grep -qE 'TLSv1([^.]|$)|TLSv1\.1|SSLv[23]'; then
        check TLS-02 HIGH FAIL "Weak protocol enabled: $proto_conf"
      else
        check TLS-02 HIGH PASS "nginx protocols restricted ($proto_conf)"
      fi
    else
      # Apache SSLProtocol tokens
      local toks safe=1
      toks=" $(echo "$proto_conf" | awk '{$1=""; print}') "
      if echo "$toks" | grep -q -- ' -all '; then
        echo "$toks" | grep -qE ' \+TLSv1( |$)| \+TLSv1\.1| \+SSLv' && safe=0
      elif echo "$toks" | grep -q -- ' all'; then
        { echo "$toks" | grep -q -- ' -TLSv1 ' && echo "$toks" | grep -q -- ' -TLSv1\.1 '; } || safe=0
      else
        echo "$toks" | grep -qE 'TLSv1( |$)|TLSv1\.1|SSLv' && safe=0
      fi
      if [ $safe -eq 1 ]; then
        check TLS-02 HIGH PASS "Apache protocols restricted ($proto_conf)"
      else
        check TLS-02 HIGH FAIL "Weak protocol enabled: $proto_conf (add -TLSv1 -TLSv1.1 -SSLv3)"
      fi
    fi
  else
    check TLS-02 MEDIUM INFO "No explicit protocol config found (verify vhost TLS settings)"
  fi

  # Certificates: find and check expiry
  local certs=()
  local c
  while IFS= read -r c; do [ -n "$c" ] && certs+=("$c"); done < <(
    grep -rhsE '^\s*ssl_certificate\s+|^\s*SSLCertificateFile\s+' /etc/nginx /etc/apache2 /etc/httpd 2>/dev/null \
      | awk '{print $2}' | sort -u
  )
  if [ ${#certs[@]} -gt 0 ]; then
    local expired=0 soon=0 checked=0 selfsigned=0
    for c in "${certs[@]}"; do
      [ -r "$c" ] || continue
      checked=$((checked+1))
      local end endepoch now epoch
      end=$(openssl x509 -in "$c" -noout -enddate 2>/dev/null | cut -d= -f2)
      [ -z "$end" ] && continue
      endepoch=$(date -d "$end" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$end" +%s 2>/dev/null)
      now=$(date +%s)
      [ -z "$endepoch" ] && continue
      if [ "$endepoch" -lt "$now" ]; then expired=$((expired+1));
      elif [ $((endepoch - now)) -lt $((30*86400)) ]; then soon=$((soon+1)); fi
      openssl x509 -in "$c" -noout -issuer 2>/dev/null | grep -qi 'issuer=.*CN *= *'"$(openssl x509 -in "$c" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')" && selfsigned=$((selfsigned+1))
    done
    if [ $checked -eq 0 ]; then
      check TLS-03 MEDIUM SKIP "Certificate files referenced but unreadable"
    elif [ $expired -gt 0 ]; then
      check TLS-03 CRITICAL FAIL "$expired certificate(s) EXPIRED"
    elif [ $soon -gt 0 ]; then
      check TLS-03 HIGH WARN "$soon certificate(s) expire within 30 days"
    else
      check TLS-03 HIGH PASS "$checked certificate(s) valid >30 days"
    fi
    [ $selfsigned -gt 0 ] && check TLS-04 MEDIUM WARN "$selfsigned self-signed certificate(s)" \
                          || check TLS-04 LOW PASS "No self-signed certificate detected"
  else
    check TLS-03 MEDIUM SKIP "No certificate path found in nginx/apache config"
  fi

  # Live probe on localhost:443
  if port_listening 443; then
    local probe proto cipher
    probe=$(echo | tmo 5 openssl s_client -connect 127.0.0.1:443 -servername localhost 2>/dev/null)
    proto=$(echo "$probe" | awk '/Protocol *:/{print $3; exit}')
    cipher=$(echo "$probe" | awk '/Cipher *:/{print $3; exit}')
    if echo "$probe" | grep -q 'Protocol *: *TLSv1.2\|Protocol *: *TLSv1.3'; then
      check TLS-05 HIGH PASS "Live handshake OK (${proto:-?} / ${cipher:-?})"
    elif [ -n "$proto" ]; then
      check TLS-05 HIGH FAIL "Live handshake uses weak protocol: $proto"
    else
      check TLS-05 MEDIUM WARN "Port 443 open but handshake failed"
    fi

    # HSTS: the header only comes back with an actual HTTP request, so a bare
    # TLS handshake can never observe it.
    local hsts
    hsts=$(printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
      | tmo 5 openssl s_client -connect 127.0.0.1:443 -servername localhost -quiet 2>/dev/null \
      | head -100 | grep -i 'strict-transport-security' | head -1)
    [ -n "$hsts" ] && check TLS-06 MEDIUM PASS "HSTS header present" \
                   || check TLS-06 MEDIUM WARN "HSTS header not observed"
  else
    check TLS-05 LOW SKIP "Nothing listening on 443"
  fi

  # Key strength
  local weakkey=0 kc=0
  for c in "${certs[@]:-}"; do
    [ -r "$c" ] || continue
    kc=$((kc+1))
    local bits; bits=$(openssl x509 -in "$c" -noout -text 2>/dev/null | awk '/Public-Key:/{print $2; exit}')
    if is_num "$bits" && [ "$bits" -lt 2048 ]; then weakkey=$((weakkey+1)); fi
  done
  [ $kc -eq 0 ] && check TLS-07 LOW SKIP "No certificate for key-strength check" \
    || { [ $weakkey -eq 0 ] && check TLS-07 HIGH PASS "All certificate keys >= 2048-bit" \
         || check TLS-07 HIGH FAIL "$weakkey certificate(s) with key < 2048-bit"; }
}

# ============================================================
# PASSWORD POLICY
# ============================================================
check_password() {
  section "PASSWORD POLICY"

  local f=/etc/login.defs
  if [ -r "$f" ]; then
    local pmax pmin plen pwarn
    pmax=$(awk '/^PASS_MAX_DAYS/{print $2}' "$f"); pmin=$(awk '/^PASS_MIN_DAYS/{print $2}' "$f")
    plen=$(awk '/^PASS_MIN_LEN/{print $2}' "$f"); pwarn=$(awk '/^PASS_WARN_AGE/{print $2}' "$f")
    is_num "$pmax" && [ "$pmax" -le 90 ] && check PWD-01 MEDIUM PASS "PASS_MAX_DAYS = $pmax" \
                                         || check PWD-01 MEDIUM WARN "PASS_MAX_DAYS = ${pmax:-unset} (recommend <= 90)"
    is_num "$pmin" && [ "$pmin" -ge 1 ] && check PWD-02 LOW PASS "PASS_MIN_DAYS = $pmin" \
                                       || check PWD-02 LOW WARN "PASS_MIN_DAYS = ${pmin:-unset} (recommend >= 1)"
    is_num "$plen" && [ "$plen" -ge 12 ] && check PWD-03 HIGH PASS "PASS_MIN_LEN = $plen" \
                                         || check PWD-03 HIGH WARN "PASS_MIN_LEN = ${plen:-unset} (recommend >= 12)"
    is_num "$pwarn" && [ "$pwarn" -ge 7 ] && check PWD-04 LOW PASS "PASS_WARN_AGE = $pwarn" \
                                          || check PWD-04 LOW WARN "PASS_WARN_AGE = ${pwarn:-unset} (recommend >= 7)"
  else
    check PWD-01 MEDIUM SKIP "/etc/login.defs not readable"
  fi

  # pwquality / cracklib
  local pq_cfg="/etc/security/pwquality.conf"
  if [ -r "$pq_cfg" ] || grep -rqs 'pam_pwquality\|pam_cracklib' /etc/pam.d 2>/dev/null; then
    local minlen; minlen=$(awk -F'=' '/^\s*minlen/{gsub(/ /,"",$2);print $2}' "$pq_cfg" 2>/dev/null)
    local dcredit ucredit lcredit ocredit
    dcredit=$(awk -F'=' '/^\s*dcredit/{gsub(/ /,"",$2);print $2}' "$pq_cfg" 2>/dev/null)
    if is_num "$minlen" && [ "$minlen" -ge 12 ]; then
      check PWD-05 HIGH PASS "pwquality minlen = $minlen"
    else
      check PWD-05 HIGH WARN "pwquality minlen = ${minlen:-default} (recommend >= 12)"
    fi
    local any=0
    for v in "$dcredit" "$ucredit" "$lcredit" "$ocredit"; do
      is_num "$v" && [ "$v" -lt 0 ] && any=1
    done
    [ $any -eq 1 ] && check PWD-06 MEDIUM PASS "pwquality enforces character classes" \
                   || check PWD-06 MEDIUM WARN "pwquality character-class rules not set"
  else
    check PWD-05 HIGH WARN "pam_pwquality/pam_cracklib not configured"
  fi

  # Lockout (faillock / tally)
  if grep -rqs 'pam_faillock\|pam_tally2' /etc/pam.d 2>/dev/null; then
    local deny; deny=$(grep -rhs 'deny=' /etc/security/faillock.conf /etc/pam.d 2>/dev/null | grep -oE 'deny=[0-9]+' | head -1 | cut -d= -f2)
    check PWD-07 HIGH PASS "Account lockout configured (pam_faillock${deny:+, deny=$deny})"
  else
    check PWD-07 HIGH WARN "No account lockout (pam_faillock/pam_tally2) configured"
  fi

  # Hashing algorithm in /etc/shadow
  if [ -r /etc/shadow ]; then
    local md5=0 sha=0 yes=0
    while IFS=: read -r _ pw _; do
      case "$pw" in
        \$1\$*) md5=$((md5+1)) ;;
        \$5\$*|\$6\$*) sha=$((sha+1)) ;;
        \$y\$*) yes=$((yes+1)) ;;
      esac
    done < /etc/shadow
    if [ $md5 -gt 0 ]; then
      check PWD-08 HIGH FAIL "$md5 account(s) use MD5 password hash"
    elif [ $yes -gt 0 ] || [ $sha -gt 0 ]; then
      check PWD-08 HIGH PASS "Strong password hash in use (yescrypt/sha512)"
    else
      check PWD-08 MEDIUM INFO "Hash algorithm not determined from /etc/shadow"
    fi

    # Empty passwords
    local empty; empty=$(awk -F: 'length($2)==0{c++} END{print c+0}' /etc/shadow)
    [ "$empty" -eq 0 ] && check PWD-09 CRITICAL PASS "No account with empty password" \
                       || check PWD-09 CRITICAL FAIL "$empty account(s) with EMPTY password"

    # Shadow permissions
    local m; m=$(stat -c '%a' /etc/shadow 2>/dev/null || stat -f '%Lp' /etc/shadow 2>/dev/null)
    case "$m" in
      640|600|000|640) check PWD-10 HIGH PASS "/etc/shadow permissions = $m" ;;
      *) check PWD-10 HIGH FAIL "/etc/shadow permissions = $m (should be 640 or stricter)" ;;
    esac
  else
    check PWD-08 MEDIUM SKIP "/etc/shadow not readable (run as root)"
  fi

  # Root account status
  local rootstat; rootstat=$(passwd -S root 2>/dev/null | awk '{print $2}')
  case "$rootstat" in
    L) check PWD-11 MEDIUM PASS "root account locked" ;;
    P) check PWD-11 MEDIUM WARN "root account has a password (prefer locked + sudo)" ;;
    *) check PWD-11 LOW INFO "root account status: ${rootstat:-unknown}" ;;
  esac

  # Sudo NOPASSWD
  if [ -r /etc/sudoers ] || [ -d /etc/sudoers.d ]; then
    local np
    np=$(grep -rhs 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^[[:space:]]*#' | wc -l | tr -d ' ')
    [ "$np" -eq 0 ] && check PWD-12 MEDIUM PASS "No sudo NOPASSWD rules" \
                    || check PWD-12 MEDIUM WARN "$np sudo NOPASSWD rule(s) present"
  fi
}

# ============================================================
# SYSTEM / VERSION
# ============================================================
check_system() {
  section "SYSTEM & VERSION"

  check SYS-01 LOW INFO "OS: ${OS_NAME:-unknown} | Kernel: $(uname -r 2>/dev/null) | Uptime: $(uptime -p 2>/dev/null | sed 's/^up //')"

  # Pending updates
  if [ $QUICK -eq 0 ]; then
    local upgrades=""
    case "$PKG" in
      apt-get) upgrades=$(apt-get -s upgrade 2>/dev/null | awk '/^[0-9]+ upgraded/{print $1}') ;;
      dnf)     upgrades=$(dnf -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]' ) ;;
      yum)     upgrades=$(yum -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]') ;;
      zypper)  upgrades=$(zypper -q list-updates 2>/dev/null | grep -c 'v  |') ;;
      *)       upgrades="" ;;
    esac
    if is_num "$upgrades"; then
      num_gt "$upgrades" 0 && check SYS-02 HIGH WARN "$upgrades package update(s) pending" \
                          || check SYS-02 HIGH PASS "No pending package updates"
    else
      check SYS-02 MEDIUM INFO "Pending updates unknown (no supported package manager)"
    fi
  else
    check SYS-02 MEDIUM SKIP "Pending updates skipped (--quick)"
  fi

  # Automatic security updates
  if [ -r /etc/apt/apt.conf.d/20auto-upgrades ]; then
    grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null \
      && check SYS-03 MEDIUM PASS "Unattended security upgrades enabled" \
      || check SYS-03 MEDIUM WARN "Unattended upgrades not enabled"
  elif have dnf; then
    grep -qs 'apply_updates.*yes\|upgrade_type.*security' /etc/dnf/automatic.conf 2>/dev/null \
      && check SYS-03 MEDIUM PASS "dnf automatic updates configured" \
      || check SYS-03 MEDIUM WARN "dnf automatic updates not configured"
  else
    check SYS-03 MEDIUM INFO "Automatic update mechanism not detected"
  fi

  # Reboot required (Debian flag or RHEL needs-restarting)
  if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
    check SYS-04 MEDIUM WARN "Reboot required (kernel/library update pending)"
  elif have needs-restarting && ! needs-restarting -r >/dev/null 2>&1; then
    check SYS-04 MEDIUM WARN "Reboot required (needs-restarting)"
  else
    check SYS-04 LOW PASS "No reboot required"
  fi

  # SELinux / AppArmor
  local mac=""
  if have getenforce; then
    local se; se=$(getenforce 2>/dev/null)
    mac="SELinux ${se:-unknown}"
    [ "$se" = "Enforcing" ] && check SYS-05 HIGH PASS "SELinux enforcing" \
                            || check SYS-05 HIGH WARN "SELinux = $se"
  fi
  if [ -z "$mac" ] && [ -d /sys/kernel/security/apparmor ]; then
    if have aa-status; then
      local ap; ap=$(aa-status 2>/dev/null | awk '/profiles are loaded/{print $1}' | head -1)
      check SYS-05 HIGH PASS "AppArmor active (${ap:-?} profiles)"
    else
      check SYS-05 HIGH WARN "AppArmor present but aa-status missing"
    fi
  elif [ -z "$mac" ]; then
    check SYS-05 HIGH WARN "No SELinux/AppArmor enforcing detected"
  fi

  # sysctl network hardening
  local s_bad=""
  _s() { local k=$1 want=$2 cur; cur=$(sysctl -n "$k" 2>/dev/null); [ "$cur" = "$want" ] || s_bad="$s_bad $k=$cur"; }
  _s net.ipv4.conf.all.accept_redirects 0
  _s net.ipv4.conf.all.send_redirects 0
  _s net.ipv4.conf.all.accept_source_route 0
  _s net.ipv4.tcp_syncookies 1
  _s net.ipv4.conf.all.rp_filter 1
  _s net.ipv4.conf.all.log_martians 1
  _s kernel.randomize_va_space 2
  [ -z "$s_bad" ] && check SYS-06 MEDIUM PASS "Common sysctl network hardening set" \
                  || check SYS-06 MEDIUM WARN "sysctl not hardened:$s_bad"

  # IP forwarding (off unless router)
  local fwd; fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
  [ "$fwd" = "0" ] && check SYS-07 LOW PASS "IP forwarding disabled" \
                   || check SYS-07 LOW INFO "IP forwarding enabled (expected only for routers/containers)"

  # ASLR already in sysctl; core dumps
  local cd; cd=$(sysctl -n fs.suid_dumpable 2>/dev/null)
  [ "$cd" = "0" ] && check SYS-08 MEDIUM PASS "SUID core dumps disabled" \
                  || check SYS-08 MEDIUM WARN "fs.suid_dumpable = ${cd:-?} (recommend 0)"

  # /tmp mount options
  local tmpopts; tmpopts=$(findmnt -no OPTIONS /tmp 2>/dev/null)
  if [ -n "$tmpopts" ]; then
    echo "$tmpopts" | grep -q 'nosuid' && echo "$tmpopts" | grep -q 'nodev' \
      && check SYS-09 LOW PASS "/tmp mounted nosuid,nodev ($tmpopts)" \
      || check SYS-09 LOW WARN "/tmp mount options: $tmpopts (add nosuid,nodev,noexec)"
  else
    check SYS-09 LOW INFO "/tmp is not a separate mount"
  fi
  # Time sync
  if have timedatectl; then
    timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes \
      && check SYS-10 MEDIUM PASS "System clock NTP-synchronized" \
      || check SYS-10 MEDIUM WARN "System clock not NTP-synchronized"
  elif have chronyc; then
    chronyc tracking >/dev/null 2>&1 && check SYS-10 MEDIUM PASS "chrony time sync active" \
                                     || check SYS-10 MEDIUM WARN "chrony not tracking"
  else
    check SYS-10 MEDIUM INFO "Time sync status unknown"
  fi

  # auditd
  svc_active auditd && check SYS-11 MEDIUM PASS "auditd running" \
                    || check SYS-11 MEDIUM WARN "auditd not running (no syscall audit trail)"

  # PATH world-writable
  local pathbad=0
  local -a _paths=()
  IFS=: read -ra _paths <<< "${PATH:-}"
  for d in "${_paths[@]}"; do
    [ -d "$d" ] || continue
    [ -n "$(find "$d" -maxdepth 0 -perm -0002 2>/dev/null)" ] && pathbad=$((pathbad+1))
  done
  [ $pathbad -eq 0 ] && check SYS-12 MEDIUM PASS "No world-writable directory in PATH" \
                     || check SYS-12 MEDIUM FAIL "$pathbad world-writable PATH dir(s)"

  # umask
  local um; um=$(umask 2>/dev/null)
  case "$um" in
    0022|022|0027|027|0077|077) check SYS-13 LOW PASS "Default umask = $um" ;;
    *) check SYS-13 LOW WARN "Default umask = ${um:-?} (recommend 022 or stricter)" ;;
  esac

  # Listening services summary
  local listen
  listen=$( { ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null; } | awk 'NR>1{print $1"/"$5}' | sort -u | head -12 | tr '\n' ' ')
  check SYS-14 LOW INFO "Listening sockets: ${listen:-none}"

  # Cron permissions
  local cronbad=0
  for f in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [ -e "$f" ] || continue
    [ -n "$(find "$f" -maxdepth 0 -perm -002 2>/dev/null)" ] && cronbad=$((cronbad+1))
  done
  [ $cronbad -eq 0 ] && check SYS-15 LOW PASS "Cron paths not group/other-writable" \
                     || check SYS-15 LOW WARN "$cronbad cron path(s) group/other-writable"

  # Legacy/insecure services
  local legacy=""
  for s in telnet telnetd rsh rlogind rexec tftp vsftpd proftpd pure-ftpd; do
    if svc_active "$s" 2>/dev/null; then legacy="$legacy $s"; fi
  done
  for p in telnet ftp rsh tftp; do
    if [ -f "/etc/xinetd.d/$p" ] && grep -qs 'disable.*=.*no' "/etc/xinetd.d/$p" 2>/dev/null; then
      legacy="$legacy xinetd:$p"
    fi
  done
  [ -z "$legacy" ] && check SYS-16 HIGH PASS "No legacy insecure service running (telnet/ftp/rsh/tftp)" \
                   || check SYS-16 HIGH FAIL "Legacy insecure service(s) running:$legacy"
}

# ============================================================
# PHP SECURITY
# ============================================================
check_php() {
  section "PHP SECURITY"

  if ! have php; then
    check PHP-00 MEDIUM SKIP "PHP not installed"
    return
  fi

  local ver; ver=$(php -r 'echo PHP_VERSION;' 2>/dev/null); ver=${ver:-0}
  local major; major=${ver%%.*}
  local minor; minor=$(echo "$ver" | cut -d. -f2)
  if is_num "$major" && [ "$major" -ge 8 ] && is_num "$minor" && { [ "$major" -gt 8 ] || [ "$minor" -ge 4 ]; }; then
    check PHP-01 HIGH PASS "PHP $ver (>= 8.4 supported)"
  elif is_num "$major" && [ "$major" -ge 8 ]; then
    check PHP-01 MEDIUM WARN "PHP $ver (upgrade to 8.4 for current security patches)"
  else
    check PHP-01 CRITICAL FAIL "PHP $ver is EOL (no security support)"
  fi

  local sapi; sapi=$(php -r 'echo PHP_SAPI;' 2>/dev/null)
  [ "$sapi" = "fpm-fcgi" ] && check PHP-02 HIGH PASS "PHP SAPI = fpm-fcgi (FPM)" \
    || check PHP-02 MEDIUM INFO "PHP SAPI = ${sapi:-unknown}; verify the FPM pool ini (not CLI)"

  # CVE mitigation (PHP2Shell family)
  if [ "$(php_ini_bool session.upload_progress.enabled)" = "0" ]; then
    check PHP-03 CRITICAL PASS "session.upload_progress.enabled = Off (CVE mitigation)"
  else
    check PHP-03 CRITICAL FAIL "session.upload_progress.enabled = On (enable-off for CVE mitigation)"
  fi

  [ "$(php_ini_bool cgi.fix_pathinfo)" = "1" ] \
    && check PHP-04 HIGH FAIL "cgi.fix_pathinfo = On (path-info upload execution risk with FPM)" \
    || check PHP-04 HIGH PASS "cgi.fix_pathinfo = Off"

  [ "$(php_ini_bool expose_php)" = "1" ] \
    && check PHP-05 MEDIUM WARN "expose_php = On (version leaked)" \
    || check PHP-05 MEDIUM PASS "expose_php = Off"

  [ "$(php_ini_bool display_errors)" = "1" ] \
    && check PHP-06 HIGH FAIL "display_errors = On (information disclosure)" \
    || check PHP-06 HIGH PASS "display_errors = Off"

  [ "$(php_ini_bool allow_url_include)" = "1" ] \
    && check PHP-07 HIGH FAIL "allow_url_include = On (remote code inclusion)" \
    || check PHP-07 HIGH PASS "allow_url_include = Off"

  [ "$(php_ini_bool allow_url_fopen)" = "1" ] \
    && check PHP-08 LOW WARN "allow_url_fopen = On (needed by some apps; restrict if unused)" \
    || check PHP-08 LOW PASS "allow_url_fopen = Off"

  [ "$(php_ini_bool session.cookie_httponly)" = "1" ] \
    && check PHP-09 MEDIUM PASS "session.cookie_httponly = On" \
    || check PHP-09 MEDIUM WARN "session.cookie_httponly = Off"

  [ "$(php_ini_bool session.cookie_secure)" = "1" ] \
    && check PHP-10 MEDIUM PASS "session.cookie_secure = On" \
    || check PHP-10 MEDIUM WARN "session.cookie_secure = Off (cookies sent over HTTP)"

  [ "$(php_ini_bool session.use_only_cookies)" = "1" ] \
    && check PHP-11 MEDIUM PASS "session.use_only_cookies = On" \
    || check PHP-11 MEDIUM FAIL "session.use_only_cookies = Off (session fixation risk)"

  [ "$(php_ini_bool session.use_strict_mode)" = "1" ] \
    && check PHP-12 MEDIUM PASS "session.use_strict_mode = On" \
    || check PHP-12 MEDIUM WARN "session.use_strict_mode = Off (session fixation risk)"

  local ss; ss=$(php_ini_get session.cookie_samesite)
  case "$ss" in
    Lax|Strict|lax|strict) check PHP-13 LOW PASS "session.cookie_samesite = $ss" ;;
    *) check PHP-13 LOW WARN "session.cookie_samesite = ${ss:-unset}" ;;
  esac

  local df; df=$(php_ini_get disable_functions)
  local need="exec system passthru shell_exec proc_open popen" missing="" fn
  for fn in $need; do echo "$df" | grep -qw "$fn" || missing="$missing $fn"; done
  [ -z "$missing" ] && check PHP-14 MEDIUM PASS "disable_functions covers dangerous calls" \
                    || check PHP-14 MEDIUM WARN "disable_functions missing:$missing"

  local ob; ob=$(php_ini_get open_basedir)
  [ -n "$ob" ] && check PHP-15 MEDIUM PASS "open_basedir = $ob" \
               || check PHP-15 MEDIUM WARN "open_basedir not set"

  local umf pms
  umf=$(php_ini_get upload_max_filesize); pms=$(php_ini_get post_max_size)
  check PHP-16 LOW INFO "upload_max_filesize=${umf:-?} post_max_size=${pms:-?} (align with app limits)"
}

# ============================================================
# DATABASE HARDENING
# ============================================================
check_db() {
  section "DATABASE HARDENING"

  local engine=""
  if svc_active mysql; then engine=mysql
  elif svc_active mariadb; then engine=mariadb
  elif svc_active postgresql; then engine=postgresql
  fi

  if [ -z "$engine" ]; then
    check DB-00 LOW SKIP "No MySQL/MariaDB/PostgreSQL service running"
    return
  fi
  check DB-01 HIGH PASS "Database service running: $engine"

  if [ "$engine" = "postgresql" ]; then
    # PostgreSQL
    local psql_run=""
    if have psql; then
      if is_root && have runuser; then psql_run="runuser -u postgres -- psql -tAc"
      elif is_root; then psql_run="su - postgres -c"; fi
    fi
    if [ -n "$psql_run" ]; then
      local la pe ssl
      if [ "$psql_run" = "runuser -u postgres -- psql -tAc" ]; then
        la=$(runuser -u postgres -- psql -tAc "SHOW listen_addresses" 2>/dev/null)
        pe=$(runuser -u postgres -- psql -tAc "SHOW password_encryption" 2>/dev/null)
        ssl=$(runuser -u postgres -- psql -tAc "SHOW ssl" 2>/dev/null)
      else
        la=$(su - postgres -c "psql -tAc \"SHOW listen_addresses\"" 2>/dev/null)
        pe=$(su - postgres -c "psql -tAc \"SHOW password_encryption\"" 2>/dev/null)
        ssl=$(su - postgres -c "psql -tAc \"SHOW ssl\"" 2>/dev/null)
      fi
      case "$la" in
        ""|localhost|127.0.0.1) check DB-02 HIGH PASS "PostgreSQL listen_addresses = ${la:-localhost}" ;;
        *) check DB-02 HIGH WARN "PostgreSQL listens on '${la}' (ensure firewall restricts access)" ;;
      esac
      case "$pe" in
        scram-sha-256) check DB-03 HIGH PASS "PostgreSQL password_encryption = scram-sha-256" ;;
        md5) check DB-03 HIGH FAIL "PostgreSQL password_encryption = md5 (use scram-sha-256)" ;;
        *) check DB-03 MEDIUM INFO "PostgreSQL password_encryption = ${pe:-unknown}" ;;
      esac
      [ "$ssl" = "on" ] && check DB-04 MEDIUM PASS "PostgreSQL SSL enabled" \
                        || check DB-04 MEDIUM WARN "PostgreSQL SSL disabled"
      local trust
      trust=$(grep -rhsE '^[^#].*\btrust\b' /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | grep -vE 'local|127\.0\.0\.1|::1' | head -3)
      [ -z "$trust" ] && check DB-05 HIGH PASS "No trust auth in pg_hba for remote hosts" \
                      || check DB-05 CRITICAL FAIL "pg_hba trusts remote clients without password"
    else
      check DB-02 MEDIUM SKIP "psql not usable as postgres (run as root)"
    fi
    return
  fi

  # MySQL / MariaDB
  if ! have mysql; then
    check DB-02 MEDIUM SKIP "mysql client missing (cannot query server)"
  else
    local bind remote_root anon empty lif secure
    bind=$(mysql -N -B -e "SELECT @@bind_address" 2>/dev/null)
    if [ -z "$bind" ]; then
      check DB-02 MEDIUM SKIP "Cannot query MySQL as current user (needs DB credentials)"
    else
      case "$bind" in
        0.0.0.0|*|::) check DB-02 HIGH WARN "MySQL bind_address = '$bind' (bound to all interfaces)" ;;
        localhost|127.0.0.1|::1) check DB-02 HIGH PASS "MySQL bind_address = '$bind'" ;;
        *) check DB-02 MEDIUM INFO "MySQL bind_address = '$bind'" ;;
      esac

      remote_root=$(mysql -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null)
      if is_num "$remote_root" && [ "$remote_root" -gt 0 ]; then
        check DB-03 CRITICAL FAIL "$remote_root remote root account(s) in mysql.user"
      else
        check DB-03 HIGH PASS "No remote root account"
      fi

      anon=$(mysql -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE user=''" 2>/dev/null)
      is_num "$anon" && [ "$anon" -gt 0 ] \
        && check DB-04 HIGH FAIL "$anon anonymous account(s)" \
        || check DB-04 HIGH PASS "No anonymous accounts"

      empty=$(mysql -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE authentication_string='' AND plugin NOT IN ('auth_socket','unix_socket')" 2>/dev/null)
      is_num "$empty" && [ "$empty" -gt 0 ] \
        && check DB-05 CRITICAL FAIL "$empty account(s) with empty password" \
        || check DB-05 CRITICAL PASS "No passwordless accounts (non-socket)"

      lif=$(mysql -N -B -e "SELECT @@local_infile" 2>/dev/null)
      [ "$lif" = "0" ] && check DB-06 MEDIUM PASS "local_infile disabled" \
                       || check DB-06 MEDIUM WARN "local_infile = ${lif:-?} (disable unless needed)"

      secure=$(mysql -N -B -e "SELECT @@require_secure_transport" 2>/dev/null)
      [ "$secure" = "1" ] && check DB-07 MEDIUM PASS "require_secure_transport = On" \
                         || check DB-07 MEDIUM WARN "require_secure_transport = Off (TLS not enforced)"
    fi
  fi

  # Config file permissions
  local cnf bad=0
  for cnf in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf; do
    [ -r "$cnf" ] || continue
    [ -n "$(find "$cnf" -maxdepth 0 -perm -004 2>/dev/null)" ] && bad=$((bad+1))
  done
  [ $bad -eq 0 ] && check DB-08 LOW PASS "DB config files not world-readable" \
                 || check DB-08 LOW WARN "$bad DB config file(s) world-readable"
}

# ============================================================
# DIFF (baseline comparison)
# ============================================================
write_current_json() {
  local first=1 i
  printf '{"findings":['
  for i in "${!F_ID[@]}"; do
    [ $first -eq 0 ] && printf ','
    first=0
    printf '{"id":"%s","severity":"%s","status":"%s"}' "${F_ID[$i]}" "${F_SEV[$i]}" "${F_STAT[$i]}"
  done
  printf ']}\n'
}

diff_report() {
  local base=$1 cur=$2
  if ! have python3; then
    echo "${Y}Diff skipped: python3 not available${N}"
    return
  fi
  python3 - "$base" "$cur" <<'PY'
import json, sys
try:
    base = json.load(open(sys.argv[1]))
    cur = json.load(open(sys.argv[2]))
except Exception as e:
    print("Diff failed: %s" % e)
    sys.exit(0)
bp = {f["id"]: f for f in base.get("findings", [])}
cp = {f["id"]: f for f in cur.get("findings", [])}
new = sorted(set(cp) - set(bp))
gone = sorted(set(bp) - set(cp))
changed = [(i, bp[i]["status"], cp[i]["status"]) for i in sorted(set(bp) & set(cp)) if bp[i]["status"] != cp[i]["status"]]
regress = [(i, a, b) for i, a, b in changed if b == "FAIL"]
fixed = [(i, a, b) for i, a, b in changed if a == "FAIL" and b != "FAIL"]
print()
print("DIFF vs baseline (%d findings)" % len(bp))
if not (new or gone or changed):
    print("  No difference.")
else:
    if regress:
        print("  Regressions (now FAIL):")
        for i, a, b in regress: print("    - %s: %s -> %s" % (i, a, b))
    if fixed:
        print("  Fixed (was FAIL):")
        for i, a, b in fixed: print("    + %s: %s -> %s" % (i, a, b))
    other = [c for c in changed if c not in regress and c not in fixed]
    if other:
        print("  Changed:")
        for i, a, b in other: print("    ~ %s: %s -> %s" % (i, a, b))
    if new:
        print("  New checks: " + ", ".join(new))
    if gone:
        print("  Checks no longer present: " + ", ".join(gone))
PY
}

# ============================================================
# REPORT
# ============================================================
print_report() {
  local score="N/A" grade="N/A" score_json="null"
  read -r score grade <<< "$(score_and_grade "$W_PASS" "$W_TOTAL")"
  [ "$score" != "N/A" ] && score_json="$score"

  local crit_high_fail=0
  local i
  for i in "${!F_ID[@]}"; do
    if [ "${F_STAT[$i]}" = "FAIL" ] && ! is_accepted "${F_ID[$i]}"; then
      case "${F_SEV[$i]}" in CRITICAL|HIGH) crit_high_fail=$((crit_high_fail+1)) ;; esac
    fi
  done

  if [ $JSON -eq 1 ]; then
    local first=1
    printf '{"host":"%s","os":"%s","kernel":"%s","score":%s,"grade":"%s","summary":{"total":%d,"pass":%d,"warn":%d,"fail":%d,"skip":%d,"info":%d},"findings":[' \
      "$HOSTNAME_S" "${OS_NAME:-unknown}" "$(uname -r 2>/dev/null)" "$score_json" "$grade" \
      "$TOTAL" "$N_PASS" "$N_WARN" "$N_FAIL" "$N_SKIP" "$N_INFO"
    for i in "${!F_ID[@]}"; do
      [ $first -eq 0 ] && printf ','
      first=0
      printf '{"id":"%s","section":"%s","severity":"%s","status":"%s","message":"%s"}' \
        "${F_ID[$i]}" "${F_SECTION[$i]}" "${F_SEV[$i]}" "${F_STAT[$i]}" "$(json_esc "${F_MSG[$i]}")"
    done
    printf ']}\n'
    [ "$crit_high_fail" -gt 0 ] && return 1 || return 0
  fi

  # Human summary
  echo
  echo "${B}============================================================${N}"
  echo "${B}BENCHMARK SUMMARY${N}"
  echo "------------------------------------------------------------"
  printf '  %-10s %s\n' "Total"   "$TOTAL"
  printf '  %-10s %s\n' "Pass"    "$N_PASS"
  printf '  %-10s %s\n' "Warn"    "$N_WARN"
  printf '  %-10s %s\n' "Fail"    "$N_FAIL"
  printf '  %-10s %s\n' "Skip"    "$N_SKIP"
  printf '  %-10s %s\n' "Info"    "$N_INFO"
  printf '  %-10s %s / 100\n' "Score" "$score"
  printf '  %-10s %s\n' "Grade"   "$grade"
  printf '  %-10s %s\n' "Critical/High failures" "$crit_high_fail"
  echo "------------------------------------------------------------"

  # Critical & high failures list (accepted items are marked, not blocking)
  local any=0
  for i in "${!F_ID[@]}"; do
    if [ "${F_STAT[$i]}" = "FAIL" ]; then
      case "${F_SEV[$i]}" in
        CRITICAL|HIGH)
          if is_accepted "${F_ID[$i]}"; then
            printf '  %s %s %s: %s (accepted)\n' "${C}~${N}" "${F_ID[$i]}" "${F_SEV[$i]}" "${F_MSG[$i]}"
          else
            [ $any -eq 0 ] && { echo "${R}Priority fixes:${N}"; any=1; }
            printf '  - %s %s: %s\n' "${F_ID[$i]}" "${F_SEV[$i]}" "${F_MSG[$i]}"
          fi
          ;;
      esac
    fi
  done
  [ $any -eq 0 ] && echo "${G}No blocking CRITICAL/HIGH failures.${N}"

  echo
  echo "Full report: $REPORT"
  [ "$crit_high_fail" -gt 0 ] && return 1 || return 0
}

# ---------- Run sections ----------
[ $RUN_SSH -eq 1 ] && check_ssh
[ $RUN_FW  -eq 1 ] && check_firewall
[ $RUN_WEB -eq 1 ] && check_web
[ $RUN_TLS -eq 1 ] && check_tls
[ $RUN_PHP -eq 1 ] && check_php
[ $RUN_DB  -eq 1 ] && check_db
[ $RUN_PWD -eq 1 ] && check_password
[ $RUN_SYS -eq 1 ] && check_system

print_report
rc=$?

# Baseline diff (human mode only)
if [ -n "$DIFF_FILE" ] && [ $JSON -eq 0 ]; then
  if [ -r "$DIFF_FILE" ]; then
    _cur=$(mktemp 2>/dev/null || echo "/tmp/hc-cur.$$")
    write_current_json > "$_cur"
    diff_report "$DIFF_FILE" "$_cur"
    rm -f "$_cur"
  else
    echo "${Y}Diff skipped: baseline '$DIFF_FILE' not readable${N}"
  fi
fi

# Append findings to report file (human format)
if [ $JSON -eq 0 ]; then
  { echo; echo "=== FINDINGS ==="; } >> "$REPORT" 2>/dev/null || true
  for i in "${!F_ID[@]}"; do
    printf '%-9s %-8s %-5s %-22s %s\n' "${F_ID[$i]}" "${F_SEV[$i]}" "${F_STAT[$i]}" "${F_SECTION[$i]}" "${F_MSG[$i]}" \
      >> "$REPORT" 2>/dev/null || true
  done
fi

exit $rc
