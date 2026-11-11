#!/usr/bin/env bash
# THREATSCAN - Professional Threat Scanner v2.0
# Enterprise-grade PHP security scanner with YARA, entropy, heuristics

set -euo pipefail

# ============================================================================
# GLOBALS & DEFAULTS
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
RULES_DIR="${SCRIPT_DIR}/rules"
CONFIG_DIR="${SCRIPT_DIR}/config"
TEMPLATES_DIR="${SCRIPT_DIR}/templates"
LOGS_DIR="${SCRIPT_DIR}/logs"

PROJECT_ROOT="."
CLI_PATH_GIVEN=false
DISCOVER_MODE=false
LIST_TARGETS=false
ALL_TARGETS=false
NO_SUBPROJECTS=false
AUTO_YES=false
SCAN_TARGETS=()
SCAN_TARGET_SLUG=""
LAST_SCAN_EXIT_CODE=0
SELF_TEST=false
CONFIG_FILE=""
YARA_RULES_DIRS=()
YARA_COMPILED=""
ENTROPY_THRESHOLD=7.5
ENTROPY_MIN_LENGTH=100
HEURISTIC_THRESHOLD=70
THREADS="auto"
OUTPUT_FORMATS=("console")
OUTPUT_DIR="${SCRIPT_DIR}/reports"
QUARANTINE_DIR=""
QUARANTINE_THRESHOLD="HIGH"
QUARANTINE_PASSWORD="infected"
CUSTOM_RULES_DIR=""
GIT_CHANGED_ONLY=false
GIT_SINCE_COMMIT=""
GIT_DIFF=""
WHITELIST_PATHS=("vendor/" "node_modules/" "storage/" ".git/" ".idea/" ".vscode/" "__pycache__/" ".next/" "dist/" "build/" "coverage/" ".cache/")
WHITELIST_PATTERNS=("*.min.js" "*.bundle.js" "*.map" "*.min.css")
WHITELIST_FILES=()
MAX_FILE_SIZE="10MB"
FOLLOW_SYMLINKS=false
CACHE_DIR=""
INCREMENTAL=false
BATCH_SIZE=100
QUICK_MODE=false
SIGNATURES_ONLY=false
CHECK_DEPS=false
COMPILE_YARA=false
COMPILE_YARA_OUTPUT=""
RESTORE_QUARANTINE=""
VERBOSE=false
NO_YARA=false
FAIL_ON="HIGH"
PROGRESS=true
QUIET=false

# Keys explicitly provided on the command line. Config files must not override
# them; track them so load_config() can skip those setters.
CLI_SET=" "

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# ============================================================================
# LOAD LIBRARIES
# ============================================================================
for lib in utils discovery scanner yara entropy heuristic git quarantine output batch; do
    if [[ -f "${LIB_DIR}/${lib}.sh" ]]; then
        # shellcheck source=/dev/null
        source "${LIB_DIR}/${lib}.sh"
    fi
done

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
mark_cli() {
    case "$CLI_SET" in
        *" $1 "*) ;;
        *) CLI_SET+="$1 " ;;
    esac
}

cli_overrode() {
    case "$CLI_SET" in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

print_banner() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
╔════════════════════════════════════════════════════════════════════════════╗
║              ADVANCED THREATSCAN v2.0                     ║
║          YARA • Entropy • Heuristics • Git • Quarantine • SARIF            ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_usage() {
    cat << EOF
Usage: $0 [DIRECTORY] [OPTIONS]

Arguments:
  DIRECTORY              Path to scan (default: auto-discover web folders or current directory)

Target Discovery Options:
  -i, --discover         Auto-discover web folders on system and prompt selection
  --list-targets         List discovered web folders (system-wide or under DIRECTORY) and exit
  --all-targets          Scan all discovered web projects sequentially without prompting
  --no-subprojects       Scan DIRECTORY directly as a single root without sub-folder prompt
  -y, --yes              Skip interactive confirmation prompts

Detection Options:
  --yara-rules DIRS      YARA rules directories (comma-separated)
  --yara-compiled FILE   Pre-compiled YARA rules file
  --no-yara              Disable YARA even when the yara binary is installed
  --compile-yara DIRS    Compile YARA rules and exit
  --compile-yara-output  Output file for compiled rules
  --entropy-threshold N  Entropy threshold 0-8 (default: 7.5)
  --entropy-min-length N Min string length for entropy (default: 100)
  --heuristic-threshold N Minimum heuristic score that contributes to the
                         final score; below it the heuristic is ignored (default: 70)
  --custom-rules DIR     Custom rules directory
  --signatures-only      Only signature-based detection
  --quick                Quick scan (signatures + heuristics only)

Performance Options:
  --threads N            Thread count (default: auto, max: 32)
  --cache-dir DIR        Cache directory for incremental scans
  --incremental          Use incremental scanning
  --batch-size N         Files per batch (default: 100)
  --max-file-size SIZE   Max file size (default: 10MB)
  --follow-symlinks      Follow symbolic links

Git Options:
  --git-changed          Scan only git-changed files
  --git-since COMMIT     Scan changes since commit
  --git-diff REF1..REF2  Scan diff between refs

Output Options:
  --output FORMATS       Output formats: console,json,sarif,html,junit (comma-separated)
  --output-dir DIR       Output directory (default: ./reports)
  --fail-on LEVEL        Fail on severity: LOW,MEDIUM,HIGH,CRITICAL (default: HIGH)
  --progress             Force progress output (default: on)
  --no-progress          Hide the progress bar, keep phase messages
  -q, --quiet            Print findings only (no progress, no status)
  -v, --verbose          Verbose output

Quarantine Options:
  --quarantine DIR       Quarantine directory
  --quarantine-threshold LEVEL Quarantine threshold (default: HIGH)
  --quarantine-password  Password for ZIP (default: infected)
  --restore-quarantine FILE Restore file from quarantine

Whitelist Options:
  --whitelist-paths PATHS  Comma-separated paths to exclude
  --whitelist-patterns PATTERNS Comma-separated glob patterns
  --whitelist-files FILES Comma-separated specific files

Config Options:
  --config FILE          YAML/JSON config file

Utility:
  --check-deps           Check dependencies and exit
  --self-test            Run internal verification tests without touching servers
  -h, --help             Show this help

Exit Codes:
  0  Clean
  1  LOW/MEDIUM findings
  2  HIGH findings
  3  CRITICAL findings
  4  YARA compilation error
  5  Config error
  255 Runtime error

Examples:
  $0 /var/www/html --threads 8 --output json,sarif,html --quarantine ./quarantine
  $0 . --git-changed --config .github/scan.yaml --fail-on HIGH
  $0 /project --yara-rules ./rules --entropy-threshold 7.0 --progress
  $0 --compile-yara ./rules/yara --compile-yara-output ./compiled.yarc
  $0 --check-deps
EOF
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --yara-rules)
                IFS=',' read -ra YARA_RULES_DIRS <<< "$2"
                shift 2
                ;;
            --yara-compiled)
                YARA_COMPILED="$2"
                shift 2
                ;;
            --no-yara)
                NO_YARA=true
                shift
                ;;
            --compile-yara)
                COMPILE_YARA=true
                IFS=',' read -ra YARA_RULES_DIRS <<< "$2"
                shift 2
                ;;
            --compile-yara-output)
                COMPILE_YARA_OUTPUT="$2"
                shift 2
                ;;
            --entropy-threshold)
                ENTROPY_THRESHOLD="$2"
                mark_cli entropy_threshold
                shift 2
                ;;
            --entropy-min-length)
                ENTROPY_MIN_LENGTH="$2"
                mark_cli entropy_min_length
                shift 2
                ;;
            --heuristic-threshold)
                HEURISTIC_THRESHOLD="$2"
                mark_cli heuristic_threshold
                shift 2
                ;;
            --custom-rules)
                CUSTOM_RULES_DIR="$2"
                shift 2
                ;;
            --signatures-only)
                SIGNATURES_ONLY=true
                shift
                ;;
            --quick)
                QUICK_MODE=true
                shift
                ;;
            --threads)
                THREADS="$2"
                mark_cli threads
                shift 2
                ;;
            --cache-dir)
                CACHE_DIR="$2"
                shift 2
                ;;
            --incremental)
                INCREMENTAL=true
                shift
                ;;
            --batch-size)
                BATCH_SIZE="$2"
                shift 2
                ;;
            --max-file-size)
                MAX_FILE_SIZE="$2"
                mark_cli max_file_size
                shift 2
                ;;
            --follow-symlinks)
                FOLLOW_SYMLINKS=true
                shift
                ;;
            --git-changed)
                GIT_CHANGED_ONLY=true
                shift
                ;;
            --git-since)
                GIT_SINCE_COMMIT="$2"
                shift 2
                ;;
            --git-diff)
                GIT_DIFF="$2"
                shift 2
                ;;
            --output)
                IFS=',' read -ra OUTPUT_FORMATS <<< "$2"
                shift 2
                ;;
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --fail-on)
                FAIL_ON="$2"
                mark_cli fail_on
                shift 2
                ;;
            --progress)
                PROGRESS=true
                shift
                ;;
            --no-progress)
                PROGRESS=false
                shift
                ;;
            -q|--quiet)
                QUIET=true
                PROGRESS=false
                shift
                ;;
            --quarantine)
                QUARANTINE_DIR="$2"
                mark_cli quarantine_dir
                shift 2
                ;;
            --quarantine-threshold)
                QUARANTINE_THRESHOLD="$2"
                mark_cli quarantine_threshold
                shift 2
                ;;
            --quarantine-password)
                QUARANTINE_PASSWORD="$2"
                mark_cli quarantine_password
                shift 2
                ;;
            --restore-quarantine)
                RESTORE_QUARANTINE="$2"
                shift 2
                ;;
            --whitelist-paths)
                IFS=',' read -ra WHITELIST_PATHS <<< "$2"
                shift 2
                ;;
            --whitelist-patterns)
                IFS=',' read -ra WHITELIST_PATTERNS <<< "$2"
                shift 2
                ;;
            --whitelist-files)
                IFS=',' read -ra WHITELIST_FILES <<< "$2"
                shift 2
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --check-deps)
                CHECK_DEPS=true
                shift
                ;;
            --self-test)
                SELF_TEST=true
                shift
                ;;
            -i|--discover|--interactive)
                DISCOVER_MODE=true
                shift
                ;;
            --list-targets)
                LIST_TARGETS=true
                shift
                ;;
            --all-targets)
                ALL_TARGETS=true
                shift
                ;;
            --no-subprojects)
                NO_SUBPROJECTS=true
                shift
                ;;
            -y|--yes)
                AUTO_YES=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1" >&2
                print_usage
                exit 255
                ;;
            *)
                PROJECT_ROOT="$1"
                CLI_PATH_GIVEN=true
                shift
                ;;
        esac
    done
}

# ============================================================================
# LOAD CONFIG FILE
# ============================================================================
load_config() {
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        log "INFO" "Loading config from: $CONFIG_FILE"
        # Simple YAML/JSON parsing for key values
        if [[ "$CONFIG_FILE" == *.yaml ]] || [[ "$CONFIG_FILE" == *.yml ]]; then
            parse_yaml_config "$CONFIG_FILE"
        elif [[ "$CONFIG_FILE" == *.json ]]; then
            parse_json_config "$CONFIG_FILE"
        fi
    elif [[ -f "${CONFIG_DIR}/default.yaml" ]]; then
        parse_yaml_config "${CONFIG_DIR}/default.yaml"
    fi
}

parse_yaml_config() {
    local file="$1"
    # Simple grep-based parsing for common keys (skip comments)
    while IFS=':' read -r key value; do
        # Skip comments
        if [[ "$key" =~ ^[[:space:]]*# ]]; then continue; fi
        key=$(echo "$key" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        value=$(echo "$value" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | sed 's/^"//' | sed 's/"$//' | sed "s/^'//" | sed "s/'$//")
        # Remove inline comments
        value=$(echo "$value" | sed 's/[[:space:]]*#.*$//')
        # Remove trailing quotes that might remain
        value=$(echo "$value" | sed 's/"$//' | sed "s/'$//")
        if [[ -z "$value" ]]; then continue; fi
        case "$key" in
            threads)
                if ! cli_overrode threads; then THREADS="$value"; fi ;;
            entropy_threshold)
                if ! cli_overrode entropy_threshold; then ENTROPY_THRESHOLD="$value"; fi ;;
            heuristic_threshold)
                if ! cli_overrode heuristic_threshold; then HEURISTIC_THRESHOLD="$value"; fi ;;
            max_file_size)
                if ! cli_overrode max_file_size; then MAX_FILE_SIZE="$value"; fi ;;
            output_formats)
                IFS=',' read -ra OUTPUT_FORMATS <<< "$value" ;;
            fail_on)
                if ! cli_overrode fail_on; then FAIL_ON="$value"; fi ;;
            quarantine_dir)
                if ! cli_overrode quarantine_dir; then QUARANTINE_DIR="$value"; fi ;;
            quarantine_threshold)
                if ! cli_overrode quarantine_threshold; then QUARANTINE_THRESHOLD="$value"; fi ;;
            quarantine_password)
                if ! cli_overrode quarantine_password; then QUARANTINE_PASSWORD="$value"; fi ;;
            *) ;;
        esac
    done < <(grep -E '^\s*[a-z_]+:' "$file" | head -50)
}

parse_json_config() {
    local file="$1"
    if command -v jq >/dev/null 2>&1; then
        THREADS=$(jq -r '.scanner.threads // empty' "$file" 2>/dev/null || echo "$THREADS")
        ENTROPY_THRESHOLD=$(jq -r '.detection.entropy.threshold // empty' "$file" 2>/dev/null || echo "$ENTROPY_THRESHOLD")
        HEURISTIC_THRESHOLD=$(jq -r '.detection.heuristics.threshold // empty' "$file" 2>/dev/null || echo "$HEURISTIC_THRESHOLD")
        MAX_FILE_SIZE=$(jq -r '.scanner.max_file_size // empty' "$file" 2>/dev/null || echo "$MAX_FILE_SIZE")
        FAIL_ON=$(jq -r '.output.fail_on // empty' "$file" 2>/dev/null || echo "$FAIL_ON")
        QUARANTINE_DIR=$(jq -r '.quarantine.directory // empty' "$file" 2>/dev/null || echo "$QUARANTINE_DIR")
    fi
}

# ============================================================================
# SELF TEST
# ============================================================================
self_test() {
    local fail=0 tmp_dir
    _t() {
        if [[ "$1" == "$2" ]]; then
            echo "ok   $3"
        else
            echo "FAIL $3 (got '$1', want '$2')"
            fail=1
        fi
    }

    echo "Running ThreatScan self-test..."

    # 1. Helpers & format conversions
    _t "$(parse_size "10MB")" "10485760" "parse_size 10MB"
    _t "$(parse_size "1GB")" "1073741824" "parse_size 1GB"
    _t "$(float_gt 7.5 7.0 && echo yes || echo no)" "yes" "float_gt helper"
    _t "$(float_lt 5.0 6.0 && echo yes || echo no)" "yes" "float_lt helper"

    # 2. Shannon Entropy calculation
    local low_ent high_ent
    low_ent=$(calculate_entropy "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    high_ent=$(calculate_entropy "8f4k2Lm9Pq0VxZaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890+/==")
    _t "$(float_lt "$low_ent" 1.0 && echo yes || echo no)" "yes" "calculate_entropy low for uniform string"
    _t "$(float_gt "$high_ent" 4.0 && echo yes || echo no)" "yes" "calculate_entropy high for random base64 string"

    # 3. Temporary sandbox for scanner & discovery tests
    tmp_dir=$(mktemp -d) || return 1
    local old_root="$PROJECT_ROOT"
    PROJECT_ROOT="$tmp_dir"

    # Benign PHP vs webshell heuristics
    echo '<?php echo "Hello World"; ?>' > "$tmp_dir/clean.php"
    local clean_heur clean_score
    clean_heur=$(analyze_heuristics "$tmp_dir/clean.php")
    clean_score=$(echo "$clean_heur" | jq -r '.score // 0')
    _t "$clean_score" "0" "heuristics on benign PHP file has score 0"

    echo '<?php eval($_POST["cmd"]); ?>' > "$tmp_dir/shell.php"
    local shell_heur shell_score
    shell_heur=$(analyze_heuristics "$tmp_dir/shell.php")
    shell_score=$(echo "$shell_heur" | jq -r '.score // 0')
    _t "$( [[ $shell_score -ge 50 ]] && echo yes || echo no )" "yes" "heuristics on eval(\$_POST['cmd']) flags high risk"

    # Comment-only mentions are documentation, not executable code.
    printf '%s\n' '<?php' '// exec payload shell command' '/* backdoor eval system */' 'echo "ok";' > "$tmp_dir/documented.php"
    _t "$(analyze_heuristics "$tmp_dir/documented.php" | jq -r '.score // 0')" "0" "comment-only signal names do not score"

    # Only non-clean results are findings
    _t "$(is_finding '{"severity":"CLEAN"}' && echo yes || echo no)" "no" "clean result is not a finding"
    _t "$(is_finding '{"severity":"HIGH"}' && echo yes || echo no)" "yes" "non-clean result is a finding"

    # JSON embedded in the report must not be able to close its script tag
    _t "$(json_for_script '{"file":"</script><b>x</b>"}')" '{"file":"\u003c/script>\u003cb>x\u003c/b>"}' "json_for_script neutralises </script>"

    # A heuristic score below the threshold is ignored; at or above it counts.
    _t "$(apply_heuristic_threshold 40 70)" "0" "heuristic score below threshold is dropped"
    _t "$(apply_heuristic_threshold 80 70)" "80" "heuristic score above threshold is kept"

    # 4. Malicious .htaccess detection
    echo 'php_value auto_prepend_file "backdoor.php"' > "$tmp_dir/.htaccess"
    local htaccess_sig
    htaccess_sig=$(run_signature_detection "$(cat "$tmp_dir/.htaccess")" "$tmp_dir/.htaccess")
    _t "$(echo "$htaccess_sig" | jq -r 'map(select(.type == "malicious_config_directive")) | length > 0')" "true" "detects malicious .htaccess auto_prepend_file"

    # 5. Framework & Project Discovery
    mkdir -p "$tmp_dir/app-laravel" "$tmp_dir/app-wp/wp-includes"
    echo '{"name":"laravel/app"}' > "$tmp_dir/app-laravel/composer.json"
    echo '<?php // artisan' > "$tmp_dir/app-laravel/artisan"
    echo '<?php // wp' > "$tmp_dir/app-wp/wp-config.php"

    _t "$(detect_app_type "$tmp_dir/app-laravel")" "Laravel" "detect_app_type detects Laravel"
    _t "$(detect_app_type "$tmp_dir/app-wp")" "WordPress" "detect_app_type detects WordPress"

    # Subproject expansion
    DISCOVERED_PATHS=(); DISCOVERED_SOURCES=(); DISCOVERED_TYPES=(); DISCOVERED_COUNTS=()
    expand_web_subprojects "$tmp_dir" "test"
    _t "${#DISCOVERED_PATHS[@]}" "2" "expand_web_subprojects detects 2 distinct projects"

    # 6. Quarantine & Restore
    local q_dir="$tmp_dir/quarantine"
    mkdir -p "$q_dir"
    local old_q_dir="${QUARANTINE_DIR:-}"
    QUARANTINE_DIR="$q_dir"
    local q_path
    q_path=$(quarantine_file "$tmp_dir/shell.php" "CRITICAL" "Self-test malicious file" 12345)
    _t "$( [[ -f "$q_path" ]] && echo yes || echo no )" "yes" "quarantine_file isolates target"
    _t "$( [[ ! -f "$tmp_dir/shell.php" ]] && echo yes || echo no )" "yes" "quarantine_file removes original"
    _t "$(jq -r '.hash' "${q_path}.meta.json" 2>/dev/null | grep -q '^[a-f0-9]\{64\}$' && echo yes || echo no)" "yes" "quarantine metadata records SHA256 hash"

    restore_from_quarantine "$q_path" >/dev/null 2>&1
    _t "$( [[ -f "$tmp_dir/shell.php" ]] && echo yes || echo no )" "yes" "restore_from_quarantine restores original file"

    # Nested paths must survive the round trip, and a changed archive is refused.
    mkdir -p "$tmp_dir/app/upload"
    printf '<?php echo "x"; ?>\n' > "$tmp_dir/app/upload/x.php"
    local nested_q
    nested_q=$(quarantine_file "$tmp_dir/app/upload/x.php" "HIGH" "Self-test nested" 12345)
    restore_from_quarantine "$nested_q" >/dev/null 2>&1
    _t "$( [[ -f "$tmp_dir/app/upload/x.php" ]] && echo yes || echo no )" "yes" "restore keeps the nested original path"

    # A metadata hash that does not match the archived bytes must stop restore.
    rm -f "$tmp_dir/app/upload/x.php"
    jq '.hash = "0000000000000000000000000000000000000000000000000000000000000000"' \
        "${nested_q}.meta.json" > "${nested_q}.meta.json.tmp" && mv "${nested_q}.meta.json.tmp" "${nested_q}.meta.json"
    local restore_rc=0
    restore_from_quarantine "$nested_q" >/dev/null 2>&1 || restore_rc=$?
    _t "$( [[ $restore_rc -ne 0 && ! -f "$tmp_dir/app/upload/x.php" ]] && echo yes || echo no )" "yes" "restore refuses a hash mismatch"

    # Cleanup
    rm -rf "$tmp_dir"
    PROJECT_ROOT="$old_root"
    QUARANTINE_DIR="$old_q_dir"

    echo
    if [[ $fail -eq 0 ]]; then
        echo "ALL TESTS PASSED"
    else
        echo "SOME TESTS FAILED"
    fi
    return $fail
}

# ============================================================================
# DEPENDENCY CHECK
# ============================================================================
check_dependencies() {
    local missing=()
    local optional=()
    
    command -v bash >/dev/null || missing+=("bash")
    command -v find >/dev/null || missing+=("find")
    command -v grep >/dev/null || missing+=("grep")
    command -v awk >/dev/null || missing+=("awk")
    command -v sed >/dev/null || missing+=("sed")
    command -v date >/dev/null || missing+=("date")
    command -v stat >/dev/null || missing+=("stat")
    command -v file >/dev/null || missing+=("file")
    command -v mktemp >/dev/null || missing+=("mktemp")
    # jq is used for every result, not just optional JSON output
    command -v jq >/dev/null || missing+=("jq")
    # awk is used for entropy and float comparisons
    command -v awk >/dev/null || missing+=("awk")

    # Optional but recommended
    command -v yara >/dev/null || optional+=("yara (YARA rules)")
    command -v php >/dev/null || optional+=("php (AST parsing)")
    command -v parallel >/dev/null || optional+=("parallel (multi-threading)")
    command -v git >/dev/null || optional+=("git (git-aware features)")
    command -v clamscan >/dev/null || optional+=("clamscan (AV scanning)")
    command -v curl >/dev/null || optional+=("curl (threat intel)")
    
    echo -e "${BOLD}Required Dependencies:${NC}"
    if [[ ${#missing[@]} -eq 0 ]]; then
        echo -e "  ${GREEN}✓ All required dependencies found${NC}"
    else
        for dep in "${missing[@]}"; do
            echo -e "  ${RED}✗ Missing: $dep${NC}"
        done
    fi
    
    echo -e "\n${BOLD}Optional Dependencies:${NC}"
    for dep in "${optional[@]}"; do
        echo -e "  ${YELLOW}⚠ Optional: $dep${NC}"
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        exit 255
    fi
}

# ============================================================================
# MAIN SCAN LOGIC
# ============================================================================
run_scan() {
    local start_time=$(timestamp_ms)
    local scan_id=$(timestamp_ms)
    
    # Setup
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$LOGS_DIR"
    [[ -n "$CACHE_DIR" ]] && mkdir -p "$CACHE_DIR"
    [[ -n "$QUARANTINE_DIR" ]] && mkdir -p "$QUARANTINE_DIR"
    
    log "INFO" "Starting scan $scan_id on: $PROJECT_ROOT"
    status "${CYAN}${BOLD}[1/5]${NC} Discovering files under ${BOLD}${PROJECT_ROOT}${NC}"
    
    # Find files
    local files=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && files+=("$line")
    done < <(find_scan_files "$PROJECT_ROOT" 2>/dev/null)

    status "      ${#files[@]} file(s) found"

    # Filter files through should_scan_file (content-type sniffing + extension
    # allowlist). That is per-file filesystem work, so it reports progress too;
    # without it a large webroot sits silent for a long time before scanning.
    local filtered_files=()
    local file
    local filter_total=${#files[@]}
    local filter_index=0
    local filter_start
    filter_start=$(timestamp_ms)
    if [[ $filter_total -gt 0 ]]; then
        for file in "${files[@]}"; do
            filter_index=$((filter_index + 1))
            if should_scan_file "$file"; then
                filtered_files+=("$file")
            fi
            if [[ $((filter_index % 10)) -eq 0 ]] || [[ $filter_index -eq $filter_total ]]; then
                show_progress_bar "$filter_index" "$filter_total" "$filter_start" "Filtering"
            fi
        done
    fi
    progress_clear

    local file_count=${#filtered_files[@]}

    if [[ $file_count -eq 0 ]]; then
        log "WARN" "No files to scan"
        output_results "$(jq -n --arg id "$scan_id" --arg path "$PROJECT_ROOT" \
            '{findings: [], scan_info: {scan_id: $id, scanned_path: $path, total_files: 0}}')" 0
        return 0
    fi

    log "INFO" "Found $file_count files to scan"
    status "      ${file_count} file(s) match the scan filter"

    # Each batch writes its own JSON file here; the parent aggregates once
    local batch_dir
    batch_dir=$(mktemp -d)
    
    # Compile YARA if needed. Built-in rules are used by default whenever the
    # yara binary is present, so a plain scan is not silently signature-only.
    local yara_compiled=""
    if [[ "$NO_YARA" != "true" && "$SIGNATURES_ONLY" != "true" && "$QUICK_MODE" != "true" ]]; then
        if [[ -n "$YARA_COMPILED" ]]; then
            yara_compiled="$YARA_COMPILED"
        elif [[ ${#YARA_RULES_DIRS[@]} -gt 0 ]]; then
            status "      compiling YARA rules..."
            yara_compiled=$(compile_yara_rules "${YARA_RULES_DIRS[@]}") || yara_compiled=""
            [[ -z "$yara_compiled" ]] && status "      ${YELLOW}YARA rules unavailable, continuing without them${NC}"
        elif command -v yara >/dev/null 2>&1; then
            status "      compiling built-in YARA rules..."
            yara_compiled=$(compile_yara_rules) || yara_compiled=""
            [[ -z "$yara_compiled" ]] && status "      ${YELLOW}YARA rules unavailable, continuing without them${NC}"
        fi
    fi
    
    # Determine thread count
    local thread_count
    THREADS=$(printf '%s' "$THREADS" | tr -d "\"'")
    if [[ "$THREADS" == "auto" || -z "$THREADS" ]]; then
        thread_count=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
        thread_count=$((thread_count > 32 ? 32 : thread_count))
    else
        thread_count="$THREADS"
    fi
    [[ "$thread_count" =~ ^[0-9]+$ ]] || thread_count=4
    [[ $thread_count -lt 1 ]] && thread_count=1
    
    log "INFO" "Using $thread_count threads"
    
    # Scan files
    BATCH_DIR="$batch_dir"
    BATCH_TOTAL=$file_count
    BATCH_COMPLETED=0
    BATCH_START_MS=$(timestamp_ms)
    BATCH_PIDS=()

    local batch_files=()
    local file_index=0

    status "${CYAN}${BOLD}[2/5]${NC} Scanning ${BOLD}${file_count}${NC} file(s) with ${thread_count} thread(s), ${BATCH_SIZE} file(s) per batch"

    for file in "${filtered_files[@]}"; do
        file_index=$((file_index + 1))
        batch_files+=("$file")

        if [[ ${#batch_files[@]} -ge $BATCH_SIZE ]] || [[ $file_index -eq $file_count ]]; then
            local batch_to_scan=("${batch_files[@]}")
            log "DEBUG" "Main: dispatching batch of ${#batch_to_scan[@]} files"
            scan_batch "$batch_dir" "$yara_compiled" "$scan_id" "${batch_to_scan[@]}" &
            BATCH_PIDS+=("$!")
            batch_files=()

            # Keep at most $thread_count batches in flight. Files are counted as
            # done only when their batch is reaped, so the bar tracks real work.
            drain_batches_to "$thread_count"
            show_progress_bar "$BATCH_COMPLETED" "$file_count" "$BATCH_START_MS"
        fi
    done

    # Wait for the last batches, repainting progress until they finish.
    drain_batches
    BATCH_COMPLETED=$(batch_progress_count)
    show_progress_bar "$BATCH_COMPLETED" "$file_count" "$BATCH_START_MS"
    progress_clear

    local scan_duration=$(( $(timestamp_ms) - BATCH_START_MS ))
    local scan_rate
    scan_rate=$(awk -v c="$BATCH_COMPLETED" -v e="$scan_duration" 'BEGIN { printf "%.1f", (e > 0 ? c * 1000 / e : 0) }')
    status "      scanned ${BATCH_COMPLETED} file(s) in $(format_duration "$scan_duration") (${scan_rate} files/s)"
    status "${CYAN}${BOLD}[3/5]${NC} Collecting results"
    
    # Aggregate batch results
    local all_findings='[]'
    local batch_outputs=()
    local batch_output
    for batch_output in "${batch_dir}"/*.json; do
        [[ -f "$batch_output" ]] && batch_outputs+=("$batch_output")
    done
    if [[ ${#batch_outputs[@]} -gt 0 ]]; then
        all_findings=$(jq -s 'add // []' "${batch_outputs[@]}" 2>/dev/null) || all_findings='[]'
    fi
    rm -rf "$batch_dir"
    log "INFO" "Collected $(printf '%s' "$all_findings" | jq 'length' 2>/dev/null || echo 0) file results"
    
    local duration=$(( $(timestamp_ms) - start_time ))
    
    # Build results object
    local all_results
    all_results=$(jq -n \
        --argjson findings "$all_findings" \
        --arg scan_id "$scan_id" \
        --arg scanned_path "$PROJECT_ROOT" \
        --argjson total_files "$file_count" \
        '{
            findings: $findings,
            scan_info: {
                scan_id: $scan_id,
                scanned_path: $scanned_path,
                total_files: $total_files,
                php_only: false
            }
        }' 2>/dev/null || echo '{"findings":[],"scan_info":{"scan_id":"'$scan_id'","scanned_path":"'$PROJECT_ROOT'","total_files":'$file_count',"php_only":false}}')
    
    log "DEBUG" "All results: $all_results"
    
    # Output
    status "${CYAN}${BOLD}[4/5]${NC} Writing reports (${OUTPUT_FORMATS[*]})"
    log "DEBUG" "Calling output_results"
    output_results "$all_results" "$duration"
    log "DEBUG" "output_results returned"
    status "${CYAN}${BOLD}[5/5]${NC} Done in $(format_duration "$duration")"
    
    # Determine exit code for this scan target
    log "DEBUG" "Calling compute_exit_code"
    LAST_SCAN_EXIT_CODE=$(compute_exit_code "$all_results")
    log "DEBUG" "compute_exit_code returned $LAST_SCAN_EXIT_CODE"
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    parse_args "$@"
    
    # Normalize paths
    PROJECT_ROOT=$(realpath "$PROJECT_ROOT" 2>/dev/null || echo "$PROJECT_ROOT")
    [[ -n "$CONFIG_FILE" ]] && CONFIG_FILE=$(realpath "$CONFIG_FILE" 2>/dev/null || echo "$CONFIG_FILE")
    [[ -n "$CACHE_DIR" ]] && CACHE_DIR=$(realpath "$CACHE_DIR" 2>/dev/null || echo "$CACHE_DIR")
    [[ -n "$QUARANTINE_DIR" ]] && QUARANTINE_DIR=$(realpath "$QUARANTINE_DIR" 2>/dev/null || echo "$QUARANTINE_DIR")
    [[ -n "$OUTPUT_DIR" ]] && OUTPUT_DIR=$(realpath "$OUTPUT_DIR" 2>/dev/null || echo "$OUTPUT_DIR")
    [[ -n "$CUSTOM_RULES_DIR" ]] && CUSTOM_RULES_DIR=$(realpath "$CUSTOM_RULES_DIR" 2>/dev/null || echo "$CUSTOM_RULES_DIR")
    [[ -n "$YARA_COMPILED" ]] && YARA_COMPILED=$(realpath "$YARA_COMPILED" 2>/dev/null || echo "$YARA_COMPILED")
    [[ -n "$COMPILE_YARA_OUTPUT" ]] && COMPILE_YARA_OUTPUT=$(realpath "$COMPILE_YARA_OUTPUT" 2>/dev/null || echo "$COMPILE_YARA_OUTPUT")
    [[ -n "$RESTORE_QUARANTINE" ]] && RESTORE_QUARANTINE=$(realpath "$RESTORE_QUARANTINE" 2>/dev/null || echo "$RESTORE_QUARANTINE")
    
    for i in "${!YARA_RULES_DIRS[@]}"; do
        YARA_RULES_DIRS[i]=$(realpath "${YARA_RULES_DIRS[i]}" 2>/dev/null || echo "${YARA_RULES_DIRS[i]}")
    done
    # WHITELIST_PATHS are relative matchers (vendor/, node_modules/, ...) and
    # must stay relative: realpath would bind them to the current directory.
    
    # Load config
    load_config
    
    # Self-test
    if [[ "$SELF_TEST" == "true" ]]; then
        self_test
        exit $?
    fi

    # Check deps
    if [[ "$CHECK_DEPS" == "true" ]]; then
        check_dependencies
        exit 0
    fi
    
    # Compile YARA
    if [[ "$COMPILE_YARA" == "true" ]]; then
        compile_yara_rules "${YARA_RULES_DIRS[@]}" "$COMPILE_YARA_OUTPUT"
        exit $?
    fi
    
    # Restore quarantine
    if [[ -n "$RESTORE_QUARANTINE" ]]; then
        restore_from_quarantine "$RESTORE_QUARANTINE"
        exit $?
    fi

    # List discovered targets and exit
    if [[ "$LIST_TARGETS" == "true" ]]; then
        if [[ "$CLI_PATH_GIVEN" == "true" ]]; then
            if [[ ! -d "$PROJECT_ROOT" ]]; then
                echo -e "${RED}Error: Directory not found: $PROJECT_ROOT${NC}" >&2
                exit 255
            fi
            discover_web_targets "$PROJECT_ROOT"
        else
            discover_web_targets ""
        fi
        print_discovered_targets
        exit $?
    fi

    # Print banner early for console mode
    local banner_printed=false
    if [[ " ${OUTPUT_FORMATS[*]} " =~ " console " && "$QUIET" != "true" ]]; then
        print_banner
        banner_printed=true
    fi

    # Resolve target(s) to scan
    SCAN_TARGETS=()
    if [[ "$CLI_PATH_GIVEN" == "true" ]]; then
        if [[ ! -d "$PROJECT_ROOT" ]]; then
            echo -e "${RED}Error: Directory not found: $PROJECT_ROOT${NC}" >&2
            exit 255
        fi

        if [[ "$NO_SUBPROJECTS" != "true" ]]; then
            DISCOVERED_PATHS=()
            DISCOVERED_SOURCES=()
            DISCOVERED_TYPES=()
            DISCOVERED_COUNTS=()
            if expand_web_subprojects "$PROJECT_ROOT" "subfolder ($PROJECT_ROOT)"; then
                if [[ ${#DISCOVERED_PATHS[@]} -gt 1 || "$DISCOVER_MODE" == "true" || "$ALL_TARGETS" == "true" ]]; then
                    prompt_target_selection "$PROJECT_ROOT"
                fi
            fi
        fi

        if [[ ${#SCAN_TARGETS[@]} -eq 0 ]]; then
            SCAN_TARGETS=("$PROJECT_ROOT")
        fi
    else
        # No path specified on CLI: try system-wide web root discovery first
        discover_web_targets ""
        if [[ ${#DISCOVERED_PATHS[@]} -gt 0 ]]; then
            prompt_target_selection ""
        elif [[ "$DISCOVER_MODE" == "true" ]]; then
            # Fallback to checking current working directory subprojects
            discover_web_targets "$PROJECT_ROOT"
            if [[ ${#DISCOVERED_PATHS[@]} -gt 0 ]]; then
                prompt_target_selection "$PROJECT_ROOT"
            else
                echo -e "${RED}Error: No web directories discovered on system.${NC}" >&2
                exit 255
            fi
        else
            SCAN_TARGETS=("$PROJECT_ROOT")
        fi
    fi

    local total_targets=${#SCAN_TARGETS[@]}
    local target_idx=0
    local max_exit_code=0
    local current_target

    for current_target in "${SCAN_TARGETS[@]}"; do
        target_idx=$((target_idx + 1))
        PROJECT_ROOT="$current_target"
        LAST_SCAN_EXIT_CODE=0

        if [[ $total_targets -gt 1 ]]; then
            SCAN_TARGET_SLUG=$(basename "$PROJECT_ROOT" | tr -cs 'a-zA-Z0-9._-' '-' | sed 's/^-*//;s/-*$//')
        else
            SCAN_TARGET_SLUG=""
        fi

        if [[ " ${OUTPUT_FORMATS[*]} " =~ " console " ]]; then
            [[ "$banner_printed" == "false" && "$QUIET" != "true" ]] && { print_banner; banner_printed=true; }
            if [[ $total_targets -gt 1 ]]; then
                echo ""
                echo -e "${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${MAGENTA}${BOLD}TARGET [${target_idx}/${total_targets}]:${NC} ${BOLD}${PROJECT_ROOT}${NC}"
                echo -e "${MAGENTA}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            fi
            echo -e "${CYAN}Target:${NC} $PROJECT_ROOT"
            echo -e "${CYAN}Threads:${NC} $THREADS"
            [[ ${#YARA_RULES_DIRS[@]} -gt 0 ]] && echo -e "${CYAN}YARA Rules:${NC} ${YARA_RULES_DIRS[*]}"
            [[ -n "$YARA_COMPILED" ]] && echo -e "${CYAN}YARA Compiled:${NC} $YARA_COMPILED"
            echo -e "${CYAN}Entropy Threshold:${NC} $ENTROPY_THRESHOLD"
            echo -e "${CYAN}Heuristic Threshold:${NC} $HEURISTIC_THRESHOLD"
            [[ -n "$QUARANTINE_DIR" ]] && echo -e "${CYAN}Quarantine:${NC} $QUARANTINE_DIR (threshold: $QUARANTINE_THRESHOLD)"
            [[ "$GIT_CHANGED_ONLY" == "true" ]] && echo -e "${CYAN}Git Mode:${NC} Changed files only"
            [[ -n "$GIT_SINCE_COMMIT" ]] && echo -e "${CYAN}Git Since:${NC} $GIT_SINCE_COMMIT"
            [[ -n "$GIT_DIFF" ]] && echo -e "${CYAN}Git Diff:${NC} $GIT_DIFF"
            [[ "$INCREMENTAL" == "true" ]] && echo -e "${CYAN}Incremental:${NC} Enabled"
            echo ""
        fi

        run_scan
        if [[ $LAST_SCAN_EXIT_CODE -gt $max_exit_code ]]; then
            max_exit_code=$LAST_SCAN_EXIT_CODE
        fi
    done

    exit "$max_exit_code"
}

# Handle interrupts
trap 'echo -e "\n${YELLOW}Scan interrupted${NC}"; exit 130' INT TERM

# Run
main "$@"