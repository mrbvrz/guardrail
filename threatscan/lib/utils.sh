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
# PROGRESS BAR
# ============================================================================
show_progress_bar() {
    local current="$1"
    local total="$2"
    local width=50
    local percent=0
    [[ $total -le 0 ]] && return 0
    [[ $current -gt $total ]] && current=$total
    percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r${CYAN}[${NC}"
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "${CYAN}]${NC} %d/%d (%d%%)" "$current" "$total" "$percent"
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