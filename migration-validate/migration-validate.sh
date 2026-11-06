#!/usr/bin/env bash
#
# migration-validate.sh  (v3 - dynamic / multi-server)
# Validates rsync migration results from source server to destination server per folder,
# using profiles from profiles.conf so one script works for all servers.
#
# Run on DESTINATION server, as root:
#   sudo bash migration-validate.sh --server srv1
#   sudo bash migration-validate.sh --server srv1 --deep
#   sudo bash migration-validate.sh --server srv1 folder1 folder2
#   sudo bash migration-validate.sh --list
#   sudo bash migration-validate.sh --self-test
#   sudo bash migration-validate.sh --server srv1 --color
#   sudo bash migration-validate.sh --server srv1 -o /var/log/migration.log
#
# Override without config (legacy mode):
#   sudo HOST=user@10.0.0.5 SRC=/path/source DST=/path/dest \
#        bash migration-validate.sh folder1 folder2
#
# Prerequisites: SSH key from destination root to source server works without password.

set -u

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG="${CONFIG:-$SELF_DIR/profiles.conf}"

HOST="${HOST:-}"
SRC="${SRC:-}"
DST="${DST:-}"
FOLDERS=()
CLI_FOLDERS=()
DEEP=0
SERVER=""
LIST=0
SELF_TEST=0
FORCE_COLOR=0
OUTPUT_FILE=""

usage() {
  cat <<'USAGE'
Usage: sudo bash migration-validate.sh [options] [folder ...]

Options:
  --server, -s <name>   use server profile from profiles.conf
  --config, -c <file>   use alternate config file (default: profiles.conf in script dir)
  --list, -l            list available server profiles
  --deep                compare file contents with checksum (accurate, slow)
  --self-test           test config parser & folder logic without touching servers
  --color               force colored output (even when piped to tee/less)
  --output, -o <file>   save output to file (default: migration-<profile>-<timestamp>.log)
  -h, --help            show this help

Folder:
  Folder name on source side. If destination folder name differs, write
  src=dst, example: public_html=web

  Folders specified on CLI override the profile's folder list.

Environment variables (override profile values):
  HOST  SRC  DST  CONFIG
USAGE
}

# ---------- Helper functions ----------
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

# Counter script: runs on source (via ssh) and destination (local).
# Output: "<files> <symlinks> <folders> <bytes>" or "MISSING"
COUNT=$(cat <<'EOF'
cd "$1" 2>/dev/null || { echo MISSING; exit 0; }
f=$(find . -type f | wc -l)
l=$(find . -type l | wc -l)
d=$(find . -type d | wc -l)
b=$(find . -type f -printf '%s\n' | awk '{s+=$1} END {print s+0}')
echo "$f $l $d $b"
EOF
)

count_remote() { printf '%s\n' "$COUNT" | ssh "${SSH_OPTS[@]}" "$HOST" bash -s -- "$1" 2>/dev/null; }
count_local()  { bash -c "$COUNT" _ "$1" 2>/dev/null; }
human()        { numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || awk -v b="$1" 'BEGIN { split("B KiB MiB GiB TiB", u); for(i=5;i>=1;i--) if(b>=1024^(i-1)) { printf "%.1f %s", b/1024^(i-1), u[i]; exit } }'; }
pct()          { awk -v a="$1" -v b="$2" 'BEGIN { if (b > 0) printf "%.2f", a*100/b; else printf "0.00" }'; }
bar() {
  local n
  n=$(awk -v p="$1" 'BEGIN { printf "%d", p/5 + 0.5 }')
  [ "$n" -gt 20 ] && n=20
  printf '%*s' "$n" '' | tr ' ' '#'
  printf '%*s' "$((20-n))" '' | tr ' ' '.'
}

row() { # label source dest
  local st="${G}OK${N}"
  [ "$2" != "$3" ] && st="${R}DIFF${N}"
  printf "  %-10s %16s %16s   %s\n" "$1" "$2" "$3" "$st"
}

# "public_html" -> "public_html" ; "public_html=web" -> "public_html"
spec_src() { echo "${1%%=*}"; }

# "public_html" -> "public_html" ; "public_html=web" -> "web"
spec_dst() {
  [ "$1" = "${1#*=}" ] && echo "$1" || echo "${1#*=}"
}

# Load a single profile into HOST, SRC, DST, FOLDERS
load_profile() {
  local name=$1 line raw f
  local -a arr

  if [ ! -r "$CONFIG" ]; then
    echo "Config not found: $CONFIG" >&2
    return 2
  fi

  line=$(awk -F'|' -v n="$name" '
    BEGIN { OFS = "|" }
    /^[[:space:]]*#/  { next }
    /^[[:space:]]*$/  { next }
    { for (i = 1; i <= 5; i++) gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i) }
    $1 == n           { print; exit }
  ' "$CONFIG")

  if [ -z "$line" ]; then
    echo "Profile '$name' not found in $CONFIG" >&2
    return 2
  fi

  IFS='|' read -r _ HOST SRC DST raw <<< "$line"

  if [ -z "${HOST:-}" ] || [ -z "${SRC:-}" ] || [ -z "${DST:-}" ] || [ -z "${raw:-}" ]; then
    echo "Profile '$name' incomplete (need name|host|src|dst|folder,...)" >&2
    return 2
  fi

  FOLDERS=()
  IFS=',' read -ra arr <<< "$raw"
  for f in "${arr[@]}"; do
    f=${f//[[:space:]]/}
    [ -n "$f" ] && FOLDERS+=("$f")
  done
}

# CLI folders win over the profile list; empty CLI list keeps the profile.
merge_cli_folders() {
  [ ${#CLI_FOLDERS[@]} -gt 0 ] || return 0
  FOLDERS=("${CLI_FOLDERS[@]}")
}

list_profiles() {
  if [ ! -r "$CONFIG" ]; then
    echo "Config not found: $CONFIG" >&2
    return 2
  fi
  printf "%-10s %-22s %-30s %s\n" "PROFILE" "HOST" "SOURCE" "DEST / FOLDERS"
  awk -F'|' '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    { printf "%-10s %-22s %-30s %s  [%s]\n", $1, $2, $3, $4, $5 }
  ' "$CONFIG"
}

self_test() {
  local fail=0 tmp
  _t() {
    if [ "$1" = "$2" ]; then
      echo "ok   $3"
    else
      echo "FAIL $3 (got '$1', expected '$2')"
      fail=1
    fi
  }

  _t "$(spec_src 'public_html')" 'public_html' 'folder without mapping'
  _t "$(spec_dst 'public_html')" 'public_html' 'destination default = source'
  _t "$(spec_src 'public_html=web')" 'public_html' 'source from spec mapping'
  _t "$(spec_dst 'public_html=web')" 'web' 'destination from spec mapping'

  tmp=$(mktemp) || return 1
  cat > "$tmp" <<'EOF'
# test profile
  srvx | user@10.0.0.5 | /data/web | /var/www/html | a, b=c ,d
EOF
  CONFIG="$tmp"; HOST=''; SRC=''; DST=''; FOLDERS=()
  load_profile srvx || fail=1
  _t "$HOST" 'user@10.0.0.5' 'config: host'
  _t "$SRC" '/data/web' 'config: src'
  _t "$DST" '/var/www/html' 'config: dst'
  _t "${FOLDERS[*]:-}" 'a b=c d' 'config: folder (spaces trimmed)'
  _t "$(spec_dst "${FOLDERS[1]:-}")" 'c' 'config: mapping folder'

  # CLI folder list must survive load_profile (regression: it used to be wiped)
  FOLDERS=(a b c); CLI_FOLDERS=(x y)
  merge_cli_folders
  _t "${FOLDERS[*]}" 'x y' 'CLI folders override profile folders'
  FOLDERS=(a b c); CLI_FOLDERS=()
  merge_cli_folders
  _t "${FOLDERS[*]}" 'a b c' 'profile folders kept without CLI folders'

  rm -f "$tmp"
  [ $fail -eq 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
  return $fail
}

# ---------- Arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --deep)      DEEP=1; shift ;;
    --server|-s) SERVER="${2:-}"; [ -z "$SERVER" ] && { echo "Profile name required"; exit 2; }; shift 2 ;;
    --config|-c) CONFIG="${2:-}"; [ -z "$CONFIG" ] && { echo "Config path required"; exit 2; }; shift 2 ;;
    --list|-l)   LIST=1; shift ;;
    --self-test) SELF_TEST=1; shift ;;
    --color)     FORCE_COLOR=1; shift ;;
    --output|-o) OUTPUT_FILE="${2:-}"; [ -z "$OUTPUT_FILE" ] && { echo "Output filename required"; exit 2; }; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    --)          shift; while [ $# -gt 0 ]; do CLI_FOLDERS+=("$1"); shift; done ;;
    -*)          echo "Unknown option: $1" >&2; usage; exit 2 ;;
    *)           CLI_FOLDERS+=("$1"); shift ;;
  esac
done

# --- Guard: root check (after arg parse, so --self-test/--list can run non-root) ---
if [ "$EUID" -ne 0 ] && [ $SELF_TEST -eq 0 ] && [ $LIST -eq 0 ]; then
  echo "ERROR: This script MUST be run as root (sudo)." >&2
  echo "Run on DESTINATION server, not source server." >&2
  exit 2
fi

# --- Guard: check dependencies (only for full run, not self-test/list) ---
if [ $SELF_TEST -eq 0 ] && [ $LIST -eq 0 ]; then
  for cmd in ssh rsync find awk du df date; do
    command -v "$cmd" >/dev/null || { echo "ERROR: Command '$cmd' not found. Install it first." >&2; exit 2; }
  done
  command -v numfmt >/dev/null || echo "WARNING: 'numfmt' not found, using fallback human()" >&2
fi

if [ $SELF_TEST -eq 1 ]; then
  self_test
  exit $?
fi

if [ $LIST -eq 1 ]; then
  list_profiles
  exit $?
fi

# Save env values to override profile
ENV_HOST=$HOST; ENV_SRC=$SRC; ENV_DST=$DST

if [ -n "$SERVER" ]; then
  load_profile "$SERVER" || exit 2
fi

# Folders named on the command line override the profile's folder list
# (load_profile replaces FOLDERS, so the CLI list is kept aside until here).
merge_cli_folders

[ -n "$ENV_HOST" ] && HOST=$ENV_HOST
[ -n "$ENV_SRC" ]  && SRC=$ENV_SRC
[ -n "$ENV_DST" ]  && DST=$ENV_DST

if [ -z "$HOST" ] || [ -z "$SRC" ] || [ -z "$DST" ]; then
  echo "HOST, SRC, and DST must be set (via --server or env vars)." >&2
  echo "Run: bash $0 --help" >&2
  exit 2
fi

if [ ${#FOLDERS[@]} -eq 0 ]; then
  echo "Folder list empty. Add folders to profile or specify on CLI." >&2
  echo "Example: bash $0 --server $SERVER folder1 folder2" >&2
  exit 2
fi

# --- Setup output file (default: migration-<profile>-<timestamp>.log) ---
if [ -z "$OUTPUT_FILE" ]; then
  OUT_DIR="${SELF_DIR}/../result"
  mkdir -p "$OUT_DIR"
  TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
  SERVER_TAG="${SERVER:-manual}"
  OUTPUT_FILE="$OUT_DIR/migration-${SERVER_TAG}-${TIMESTAMP}.log"
else
  # Custom -o path: make sure the parent directory exists before tee opens it
  mkdir -p "$(dirname "$OUTPUT_FILE")" 2>/dev/null || true
fi

# Remember whether stdout was a terminal before the tee redirect below: the
# redirect turns fd 1 into a pipe, which makes a later [ -t 1 ] always false.
STDOUT_IS_TTY=0
if [ -t 1 ]; then STDOUT_IS_TTY=1; fi

# Setup logging: write to both terminal and file
exec > >(tee -a "$OUTPUT_FILE") 2>&1
echo "Output log: $OUTPUT_FILE"
echo

# Color setup (based on the pre-redirect TTY check)
if [ "$STDOUT_IS_TTY" -eq 1 ] || [ $FORCE_COLOR -eq 1 ]; then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else
  G=''; R=''; Y=''; B=''; N=''
fi

# ---------- Time (WIB UTC+7), Indonesian day/month names ----------
DAYS=(Monday Tuesday Wednesday Thursday Friday Saturday Sunday)
MONTHS=(January February March April May June July August September October November December)

wib_stamp() {
  local u dd mm yy hms
  read -r u dd mm yy hms <<< "$(date -u -d '+7 hours' '+%u %d %m %Y %H:%M:%S')"
  echo "${DAYS[$((u-1))]}, $((10#$dd)) ${MONTHS[$((10#$mm-1))]} $yy, $hms WIB (GMT+7)"
}

START_EPOCH=$(date +%s)

# ---------- Header ----------
echo "${B}MIGRATION VALIDATION${N}"
echo "Author   : Hasan Suryaman — https://mrbvrz.web.id"
[ -n "$SERVER" ] && echo "Profile  : $SERVER  ($CONFIG)"
echo "Started  : $(wib_stamp)"
echo "Source   : $HOST:$SRC"
echo "Dest     : $DST"
echo "Mode     : $([ $DEEP -eq 1 ] && echo 'deep (checksum)' || echo 'standard (size + time)')"
echo

if ! ssh "${SSH_OPTS[@]}" "$HOST" "echo ok" >/dev/null 2>&1; then
  echo "${R}Cannot SSH to $HOST without password.${N}"
  echo "Ensure ssh-copy-id has been run as root on destination."
  exit 2
fi

RS_OPTS=(-rltn --itemize-changes --delete -e "ssh ${SSH_OPTS[*]}")
[ $DEEP -eq 1 ] && RS_OPTS+=(-c)

total=${#FOLDERS[@]}
i=0
ok_n=0
bad_n=0
sum_c=0
sum_u=0
PENDING_BYTES=0
PENDING_NAMES=()
SUMMARY=()
ON_DEST=()

# ---------- Validate per folder ----------
for spec in "${FOLDERS[@]}"; do
  i=$((i+1))
  d=$(spec_src "$spec")
  dt=$(spec_dst "$spec")
  label="$d"
  [ "$d" != "$dt" ] && label="$d->$dt"

  echo "${B}[$i/$total] $label${N}"
  echo "  ------------------------------------------------------------"
  printf "  %-10s %16s %16s   %s\n" "Item" "Source" "Dest" "Status"

  rc=$(count_remote "$SRC/$d")
  lc=$(count_local "$DST/$dt")

  if [ -z "$rc" ] || [ "$rc" = "MISSING" ]; then
    echo "  ${R}Source folder not found: $SRC/$d${N}"
    echo
    SUMMARY+=("$label|-|-|-|-|SOURCE MISSING")
    bad_n=$((bad_n+1))
    [ -n "$lc" ] && [ "$lc" != "MISSING" ] && ON_DEST+=("$dt")
    continue
  fi

  read -r rf rl rd rb <<< "$rc"

  if [ -z "$lc" ] || [ "$lc" = "MISSING" ]; then
    echo "  ${R}Destination folder not found: $DST/$dt${N}"
    echo "  Size on source : $(human "$rb") ($rf files)"
    echo
    SUMMARY+=("$label|-|$(human "$rb")|-|-|NOT COPIED")
    PENDING_BYTES=$((PENDING_BYTES + rb))
    PENDING_NAMES+=("$dt")
    bad_n=$((bad_n+1))
    continue
  fi

  read -r lf ll ld lb <<< "$lc"
  ON_DEST+=("$dt")

  row "Files"    "$rf" "$lf"
  row "Symlinks" "$rl" "$ll"
  row "Folders"  "$rd" "$ld"
  row "Bytes"    "$rb" "$lb"
  printf "  %-10s %16s %16s\n" "Size" "$(human "$rb")" "$(human "$lb")"

  out=$(rsync "${RS_OPTS[@]}" "$HOST:$SRC/$d/" "$DST/$dt/" 2>&1)
  diff_n=$(grep -c '^>f' <<< "$out")
  extra_n=$(grep -c '^\*deleting' <<< "$out")
  err_n=$(grep -c -E '^(rsync:|rsync error)' <<< "$out")

  echo "  ------------------------------------------------------------"
  printf "  Files different/missing (dry-run) : %s\n" "$diff_n"
  printf "  Files only on dest (info)         : %s\n" "$extra_n"

  if [ "$diff_n" -gt 0 ]; then
    echo "  Example differing files (max 10):"
    grep '^>f' <<< "$out" | head -10 | sed 's/^/    /'
  fi
  if [ "$err_n" -gt 0 ]; then
    echo "  ${Y}Rsync errors:${N}"
    grep -E '^(rsync:|rsync error)' <<< "$out" | head -5 | sed 's/^/    /'
  fi

  if [ "$rf" = "$lf" ] && [ "$rl" = "$ll" ] && [ "$rd" = "$ld" ] \
     && [ "$rb" = "$lb" ] && [ "$diff_n" -eq 0 ] && [ "$err_n" -eq 0 ]; then
    status="COMPLETE"
    echo "  RESULT: ${G}COMPLETE${N}"
    ok_n=$((ok_n+1))
  else
    status="NEEDS REVIEW"
    echo "  RESULT: ${R}NEEDS REVIEW${N}"
    bad_n=$((bad_n+1))
  fi
  echo

  sum_c=$((sum_c + rb))
  sum_u=$((sum_u + lb))
  SUMMARY+=("$label|$rf/$lf|$(human "$rb")|$(human "$lb")|$diff_n|$status")
done

# ---------- Summary ----------
echo "${B}SUMMARY${N}"
echo "============================================================================="
printf "%-14s %-16s %-12s %-12s %-8s %s\n" "Folder" "Files (S/D)" "Source" "Dest" "Diff" "Status"
echo "-----------------------------------------------------------------------------"
for s in "${SUMMARY[@]}"; do
  IFS='|' read -r n fc sc su df st <<< "$s"
  case "$st" in
    COMPLETE) col="$G" ;;
    *)       col="$R" ;;
  esac
  printf "%-14s %-16s %-12s %-12s %-8s %s%s%s\n" "$n" "$fc" "$sc" "$su" "$df" "$col" "$st" "$N"
done
echo "-----------------------------------------------------------------------------"
printf "%-14s %-16s %-12s %-12s\n" "TOTAL" "" "$(human "$sum_c")" "$(human "$sum_u")"
echo "============================================================================="
echo "Complete: $ok_n   Needs review: $bad_n   Total folders: $total"
echo

# ---------- Storage on Destination ----------
echo "${B}DESTINATION STORAGE${N}"
read -r dev sz used avail mnt <<< "$(df -B1 --output=source,size,used,avail,target "$DST" 2>/dev/null | tail -n 1)"

if [ -z "${sz:-}" ]; then
  echo "${Y}Failed to read df for $DST${N}"
else
  used_pct=$(pct "$used" "$sz")
  free_pct=$(pct "$avail" "$sz")
  fcol="$G"
  if awk -v p="$free_pct" 'BEGIN { exit !(p < 10) }'; then fcol="$R"
  elif awk -v p="$free_pct" 'BEGIN { exit !(p < 20) }'; then fcol="$Y"; fi

  echo "Partition  : $dev (mount: $mnt)"
  echo "Capacity   : $(human "$sz")"
  echo "Used       : $(human "$used") (${used_pct}%)"
  echo "Free       : ${fcol}$(human "$avail") (${free_pct}%)${N}"

  if [ "$PENDING_BYTES" -gt 0 ]; then
    after=$((avail - PENDING_BYTES))
    echo
    echo "Folders not yet copied (${PENDING_NAMES[*]}): need ~$(human "$PENDING_BYTES")"
    if [ "$after" -gt 0 ]; then
      echo "Estimated free after copy: ${G}$(human "$after") ($(pct "$after" "$sz")%) - OK${N}"
    else
      echo "${R}SPACE INSUFFICIENT, short by ~$(human "$((-after))")${N}"
    fi
  fi

  echo
  echo "Per-folder usage (actual disk usage, du):"
  echo "-----------------------------------------------------------------------------"
  printf "%-14s %12s %12s %12s  %s\n" "Folder" "Size" "% capacity" "% migration" "Graph (% capacity)"
  echo "-----------------------------------------------------------------------------"

  du_names=()
  du_vals=()
  du_total=0
  for d in "${ON_DEST[@]}"; do
    v=$(du -sB1 "$DST/$d" 2>/dev/null | cut -f1)
    v=${v:-0}
    du_names+=("$d")
    du_vals+=("$v")
    du_total=$((du_total + v))
  done

  for idx in "${!du_names[@]}"; do
    v=${du_vals[$idx]}
    pc=$(pct "$v" "$sz")
    pm=$(pct "$v" "$du_total")
    printf "%-14s %12s %11s%% %11s%%  [%s]\n" "${du_names[$idx]}" "$(human "$v")" "$pc" "$pm" "$(bar "$pc")"
  done

  other=$((used - du_total))
  [ "$other" -lt 0 ] && other=0
  po=$(pct "$other" "$sz")
  free_bar=$(pct "$avail" "$sz")
  echo "-----------------------------------------------------------------------------"
  printf "%-14s %12s %11s%% %11s%%  [%s]\n" "Total folders" "$(human "$du_total")" "$(pct "$du_total" "$sz")" "100.00" "$(bar "$(pct "$du_total" "$sz")")"
  printf "%-14s %12s %11s%% %11s  [%s]\n" "Other (OS)" "$(human "$other")" "$po" "-" "$(bar "$po")"
  printf "%-14s %12s %11s%% %11s  [%s]\n" "Free space" "$(human "$avail")" "$free_pct" "-" "$(bar "$free_bar")"
  echo "============================================================================="
  echo "Note: '% capacity' = from total partition size; '% migration' = from total folders above."
fi

# ---------- Footer ----------
END_EPOCH=$(date +%s)
el=$((END_EPOCH - START_EPOCH))
echo
echo "Finished: $(wib_stamp)  (duration $((el/60)) min $((el%60)) sec)"

if [ "$bad_n" -gt 0 ]; then
  echo
  echo "${Y}If any folder needs review, re-run rsync for that folder:${N}"
  echo "  sudo rsync -avhP -e ssh $HOST:$SRC/<folder>/ $DST/<folder>/"
  echo "Small differences may come from logs/cache/uploads changing on source during transfer."
  exit 1
fi
echo "${G}All folders complete.${N}"
exit 0