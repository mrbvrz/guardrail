#!/usr/bin/env bash
# Utility functions for Advanced Webshell Scanner

# ============================================================================
# LOGGING
# ============================================================================
LOG_FILE="${LOGS_DIR:-/tmp}/webshell-advanced-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() {
    local level="$1"
    shift
    local msg="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
    [[ "$VERBOSE" == "true" ]] && echo "[$level] $msg" >&2
    :
}

# ============================================================================
# SEVERITY ORDER
# ============================================================================
SEVERITY_ORDER_CLEAN=0
SEVERITY_ORDER_INFO=1
SEVERITY_ORDER_LOW=2
SEVERITY_ORDER_MEDIUM=3
SEVERITY_ORDER_HIGH=4
SEVERITY_ORDER_CRITICAL=5

severity_value() {
    local severity="$1"
    case "$severity" in
        CLEAN) echo 0 ;;
        INFO) echo 1 ;;
        LOW) echo 2 ;;
        MEDIUM) echo 3 ;;
        HIGH) echo 4 ;;
        CRITICAL) echo 5 ;;
        *) echo 0 ;;
    esac
}

# ============================================================================
# COLOR HELPERS
# ============================================================================
color_for_severity() {
    case "$1" in
        CRITICAL) echo -e "${RED}${BOLD}" ;;
        HIGH) echo -e "${RED}" ;;
        MEDIUM) echo -e "${YELLOW}${BOLD}" ;;
        LOW) echo -e "${YELLOW}" ;;
        INFO) echo -e "${BLUE}" ;;
        CLEAN) echo -e "${GREEN}" ;;
        *) echo -e "${NC}" ;;
    esac
}

severity_from_score() {
    local score="$1"
    if [[ $score -ge 90 ]]; then echo "CRITICAL"
    elif [[ $score -ge 70 ]]; then echo "HIGH"
    elif [[ $score -ge 50 ]]; then echo "MEDIUM"
    elif [[ $score -ge 30 ]]; then echo "LOW"
    elif [[ $score -gt 0 ]]; then echo "INFO"
    else echo "CLEAN"
    fi
}

# ============================================================================
# FILE OPERATIONS
# ============================================================================
human_size() {
    local bytes="$1"
    if [[ $bytes -ge 1073741824 ]]; then
        echo "$((bytes / 1073741824))GB"
    elif [[ $bytes -ge 1048576 ]]; then
        echo "$((bytes / 1048576))MB"
    elif [[ $bytes -ge 1024 ]]; then
        echo "$((bytes / 1024))KB"
    else
        echo "${bytes}B"
    fi
}

is_text_file() {
    local file="$1"
    local mime_type
    mime_type=$(file -b --mime-type "$file" 2>/dev/null || echo "application/octet-stream")
    [[ "$mime_type" == text/* ]] || [[ "$mime_type" == "application/json" ]] || [[ "$mime_type" == "application/xml" ]] || [[ "$mime_type" == "application/x-php" ]]
}

get_file_size() {
    local file="$1"
    stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0
}

get_file_hash() {
    local file="$1"
    local algo="${2:-sha256}"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        echo "unavailable"
    fi
}

# ============================================================================
# WHITELIST CHECKING
# ============================================================================
is_whitelisted() {
    local file="$1"
    local rel_file="${file#$PROJECT_ROOT/}"
    
    # Check paths
    for path in "${WHITELIST_PATHS[@]:-}"; do
        [[ "$rel_file" == "$path"* ]] && return 0
        [[ "$rel_file" == */"$path"/* ]] && return 0
    done
    
    # Check patterns
    for pattern in "${WHITELIST_PATTERNS[@]:-}"; do
        [[ "$rel_file" == $pattern ]] && return 0
        [[ "$(basename "$file")" == $pattern ]] && return 0
    done
    
    # Check specific files
    for wfile in "${WHITELIST_FILES[@]:-}"; do
        [[ "$rel_file" == "$wfile" ]] && return 0
        [[ "$file" == "$wfile" ]] && return 0
    done
    
    return 1
}

# ============================================================================
# FLOAT COMPARISON (no bc/awk dependency from callers)
# ============================================================================
# Usage: float_gt 7.6 7.5 && echo greater
float_gt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'; }
float_ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a >= b) }'; }
float_lt() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a < b) }'; }

# Format a float to N decimals without bc
format_float() {
    local value="${1:-0}"
    local decimals="${2:-4}"
    awk -v v="$value" -v d="$decimals" 'BEGIN { printf "%.*f", d, v }'
}

# Trim leading/trailing whitespace
trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# ============================================================================
# STATUS / PROGRESS OUTPUT
# ============================================================================
# Everything here writes to stderr so stdout stays clean for piping reports.
# Progress is on by default: on a real webroot a silent scan is indistinguishable
# from a hung one. --quiet / --no-progress turns it off.
status() {
    [[ "${QUIET:-false}" == "true" ]] && return 0
    printf '%b\n' "$*" >&2
    return 0
}

# Erase the transient progress line before printing a permanent one.
progress_clear() {
    [[ "${QUIET:-false}" == "true" ]] && return 0
    [[ -t 2 ]] && printf '\r\033[K' >&2
    return 0
}

PROGRESS_LAST_EMIT=0

# One-line progress. On a terminal the line is rewritten in place; when stderr
# is redirected (CI, log file) a plain line is emitted so the log still moves.
# $1=current $2=total $3=start_ms (0 = no rate/ETA) $4=label
PROGRESS_LAST_LINE=""

show_progress_bar() {
    local current="${1:-0}"
    local total="${2:-0}"
    local start_ms="${3:-0}"
    local label="${4:-Scanning}"
    local width=40

    [[ "${QUIET:-false}" == "true" ]] && return 0
    [[ "${PROGRESS:-true}" == "true" ]] || return 0
    [[ $total -le 0 ]] && return 0
    [[ $current -gt $total ]] && current=$total

    local on_tty=false
    [[ -t 2 ]] && on_tty=true

    # A terminal can be repainted twice a second; a redirected stderr is
    # throttled much harder, and identical lines are dropped entirely.
    local interval=500
    [[ "$on_tty" == "true" ]] || interval=5000
    local now
    now=$(timestamp_ms)
    if [[ $current -lt $total ]] && [[ $((now - PROGRESS_LAST_EMIT)) -lt $interval ]]; then
        return 0
    fi
    PROGRESS_LAST_EMIT=$now

    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    local bar_filled bar_empty
    if [[ "$on_tty" == "true" ]]; then
        bar_filled=$(printf "%${filled}s" | tr ' ' '█')
        bar_empty=$(printf "%${empty}s" | tr ' ' '░')
    else
        bar_filled=$(printf "%${filled}s" | tr ' ' '#')
        bar_empty=$(printf "%${empty}s" | tr ' ' '.')
    fi

    local rate="" eta="" extra=""
    if [[ "$start_ms" =~ ^[0-9]+$ ]] && [[ $start_ms -gt 0 ]] && [[ $current -gt 0 ]]; then
        local elapsed=$((now - start_ms))
        if [[ $elapsed -gt 500 ]]; then
            rate=$(awk -v c="$current" -v e="$elapsed" 'BEGIN { printf "%.1f", c * 1000 / e }')
            eta=$(awk -v r="$rate" -v rem="$((total - current))" 'BEGIN { printf "%.0f", (r > 0 ? rem / r : 0) }')
            extra+=" • ${rate} files/s • ETA ${eta}s"
        fi
    fi
    # Batches still running explain a bar that is not moving.
    if [[ -n "${BATCH_PIDS+x}" ]] && [[ ${#BATCH_PIDS[@]} -gt 0 ]] && [[ $current -lt $total ]]; then
        extra+=" • ${#BATCH_PIDS[@]} batch(es) in flight"
    fi
    [[ -n "${PROGRESS_NOTE:-}" ]] && extra+=" • ${PROGRESS_NOTE}"

    local line
    if [[ "$on_tty" == "true" ]]; then
        line=$(printf '%s[%s%s]%s %d/%d (%d%%)%s%s%s' \
            "$label " "$bar_filled" "$bar_empty" "$NC" "$current" "$total" "$percent" "$DIM" "$extra" "$NC")
        printf '\r\033[K%s' "$line" >&2
    else
        line=$(printf '%s [%s%s] %d/%d (%d%%)%s' \
            "$label" "$bar_filled" "$bar_empty" "$current" "$total" "$percent" "$extra")
        [[ "$line" == "$PROGRESS_LAST_LINE" ]] && return 0
        printf '%s\n' "$line" >&2
    fi
    PROGRESS_LAST_LINE="$line"
    return 0
}

# ============================================================================
# TEMP FILE MANAGEMENT
# ============================================================================
TEMP_FILES=()
cleanup_temp_files() {
    # Preserve the script's exit status: the status of the last command run in
    # an EXIT trap otherwise replaces it (a CRITICAL scan would exit 1, not 3).
    local status=$?
    local f
    if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
        for f in "${TEMP_FILES[@]}"; do
            [[ -e "$f" ]] && rm -rf "$f"
        done
    fi
    return "$status"
}
trap cleanup_temp_files EXIT

make_temp_file() {
    local f
    f=$(mktemp)
    TEMP_FILES+=("$f")
    echo "$f"
}

# ============================================================================
# JSON HELPERS
# ============================================================================
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

json_array_from_list() {
    local input="$1"
    [[ -z "$input" ]] && echo "[]" && return
    local IFS='|'
    local items=($input)
    local result="["
    local first=true
    for item in "${items[@]}"; do
        [[ "$first" == "true" ]] && first=false || result+=","
        result+="\"$(json_escape "$item")\""
    done
    result+="]"
    echo "$result"
}

# ============================================================================
# TIME HELPERS
# ============================================================================
timestamp_ms() {
    # macOS date doesn't support %3N, use python or alternative
    if date +%s%3N 2>/dev/null | grep -q '^[0-9]*$'; then
        date +%s%3N
    else
        python3 -c 'import time; print(int(time.time() * 1000))' 2>/dev/null || \
        perl -MTime::HiRes=time -e 'print int(time() * 1000)' 2>/dev/null || \
        echo $(($(date +%s) * 1000))
    fi
}

format_duration() {
    local ms="$1"
    if [[ $ms -ge 60000 ]]; then
        echo "$((ms / 60000))m $((ms % 60000 / 1000))s"
    elif [[ $ms -ge 1000 ]]; then
        echo "$((ms / 1000))s"
    else
        echo "${ms}ms"
    fi
}

# ============================================================================
# VALIDATION
# ============================================================================
validate_threshold() {
    local value="$1"
    local min="$2"
    local max="$3"
    local name="$4"
    
    if ! [[ "$value" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo "Error: $name must be a number" >&2
        return 1
    fi
    
    if float_lt "$value" "$min"; then
        echo "Error: $name must be >= $min" >&2
        return 1
    fi
    
    if float_gt "$value" "$max"; then
        echo "Error: $name must be <= $max" >&2
        return 1
    fi
    
    return 0
}

# ============================================================================
# ARRAY HELPERS
# ============================================================================
array_contains() {
    local needle="$1"
    shift
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

array_unique() {
    local -n arr=$1
    local seen=()
    local unique=()
    for item in "${arr[@]}"; do
        if ! array_contains "$item" "${seen[@]}"; then
            seen+=("$item")
            unique+=("$item")
        fi
    done
    arr=("${unique[@]}")
}