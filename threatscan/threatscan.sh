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

PROJECT_ROOT="${1:-.}"
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
GIT_HISTORY=false
GIT_SINCE_DATE=""
WHITELIST_PATHS=("vendor/" "node_modules/" "storage/" ".git/" ".idea/" ".vscode/" "__pycache__/" ".next/" "dist/" "build/" "coverage/" ".cache/")
WHITELIST_PATTERNS=("*.min.js" "*.bundle.js" "*.map" "*.min.css")
WHITELIST_FILES=()
MAX_FILE_SIZE="10MB"
TIMEOUT=300
FOLLOW_SYMLINKS=false
CACHE_DIR=""
INCREMENTAL=false
STREAM_MODE=false
BATCH_SIZE=100
QUICK_MODE=false
SIGNATURES_ONLY=false
CHECK_DEPS=false
COMPILE_YARA=false
COMPILE_YARA_OUTPUT=""
RESTORE_QUARANTINE=""
VERBOSE=false
THREAT_INTEL=false
VT_API_KEY=""
MALWAREBAZAAR=true
CACHE_TTL=86400
FAIL_ON="HIGH"
PROGRESS=false

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
for lib in utils scanner yara entropy heuristic git quarantine output batch; do
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
  DIRECTORY              Path to scan (default: current directory)

Detection Options:
  --yara-rules DIRS      YARA rules directories (comma-separated)
  --yara-compiled FILE   Pre-compiled YARA rules file
  --compile-yara DIRS    Compile YARA rules and exit
  --compile-yara-output  Output file for compiled rules
  --entropy-threshold N  Entropy threshold 0-8 (default: 7.5)
  --entropy-min-length N Min string length for entropy (default: 100)
  --heuristic-threshold N Heuristic score threshold 0-100 (default: 70)
  --custom-rules DIR     Custom rules directory
  --signatures-only      Only signature-based detection
  --quick                Quick scan (signatures + heuristics only)

Performance Options:
  --threads N            Thread count (default: auto, max: 32)
  --cache-dir DIR        Cache directory for incremental scans
  --incremental          Use incremental scanning
  --stream-mode          Stream processing for low memory
  --batch-size N         Files per batch (default: 100)
  --max-file-size SIZE   Max file size (default: 10MB)
  --timeout SECS         Per-file timeout (default: 300)
  --follow-symlinks      Follow symbolic links

Git Options:
  --git-changed          Scan only git-changed files
  --git-since COMMIT     Scan changes since commit
  --git-diff REF1..REF2  Scan diff between refs
  --git-history          Scan entire git history
  --git-since-date DATE  Scan history since date

Output Options:
  --output FORMATS       Output formats: console,json,sarif,html,junit (comma-separated)
  --output-dir DIR       Output directory (default: ./reports)
  --fail-on LEVEL        Fail on severity: LOW,MEDIUM,HIGH,CRITICAL (default: HIGH)
  --progress             Show progress bar
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

Config & Threat Intel:
  --config FILE          YAML/JSON config file
  --threat-intel         Enable threat intelligence (VT, MalwareBazaar)
  --vt-api-key KEY       VirusTotal API key
  --cache-ttl SECS       Threat intel cache TTL (default: 86400)

Utility:
  --check-deps           Check dependencies and exit
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
            --stream-mode)
                STREAM_MODE=true
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
            --timeout)
                TIMEOUT="$2"
                mark_cli timeout
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
            --git-history)
                GIT_HISTORY=true
                shift
                ;;
            --git-since-date)
                GIT_SINCE_DATE="$2"
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
            --threat-intel)
                THREAT_INTEL=true
                shift
                ;;
            --vt-api-key)
                VT_API_KEY="$2"
                shift 2
                ;;
            --cache-ttl)
                CACHE_TTL="$2"
                shift 2
                ;;
            --check-deps)
                CHECK_DEPS=true
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
            timeout)
                if ! cli_overrode timeout; then TIMEOUT="$value"; fi ;;
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
        TIMEOUT=$(jq -r '.scanner.timeout // empty' "$file" 2>/dev/null || echo "$TIMEOUT")
        FAIL_ON=$(jq -r '.output.fail_on // empty' "$file" 2>/dev/null || echo "$FAIL_ON")
        QUARANTINE_DIR=$(jq -r '.quarantine.directory // empty' "$file" 2>/dev/null || echo "$QUARANTINE_DIR")
    fi
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
    
    # Find files
    local files=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && files+=("$line")
    done < <(find_scan_files "$PROJECT_ROOT" 2>/dev/null)

    # Filter files through should_scan_file
    local filtered_files=()
    local file
    if [[ ${#files[@]} -gt 0 ]]; then
        for file in "${files[@]}"; do
            if should_scan_file "$file"; then
                filtered_files+=("$file")
            fi
        done
    fi

    local file_count=${#filtered_files[@]}

    if [[ $file_count -eq 0 ]]; then
        log "WARN" "No files to scan"
        output_results "$(jq -n --arg id "$scan_id" --arg path "$PROJECT_ROOT" \
            '{findings: [], scan_info: {scan_id: $id, scanned_path: $path, total_files: 0}}')" 0
        return 0
    fi

    log "INFO" "Found $file_count files to scan"
    [[ "$PROGRESS" == "true" ]] && show_progress_bar 0 "$file_count"

    # Each batch writes its own JSON file here; the parent aggregates once
    local batch_dir
    batch_dir=$(mktemp -d)
    
    # Compile YARA if needed
    local yara_compiled=""
    if [[ ${#YARA_RULES_DIRS[@]} -gt 0 ]] && [[ -z "$YARA_COMPILED" ]]; then
        yara_compiled=$(compile_yara_rules "${YARA_RULES_DIRS[@]}") || yara_compiled=""
    elif [[ -n "$YARA_COMPILED" ]]; then
        yara_compiled="$YARA_COMPILED"
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
    local scanned=0
    local pids=()
    local batch_files=()
    local file_index=0

    for file in "${filtered_files[@]}"; do
        file_index=$((file_index + 1))
        batch_files+=("$file")

        if [[ ${#batch_files[@]} -ge $BATCH_SIZE ]] || [[ $file_index -eq $file_count ]]; then
            local batch_to_scan=("${batch_files[@]}")
            log "DEBUG" "Main: dispatching batch of ${#batch_to_scan[@]} files"
            scan_batch "$batch_dir" "$yara_compiled" "$scan_id" "${batch_to_scan[@]}" &
            pids+=("$!")
            batch_files=()

            # Limit concurrent batches, reaping finished children
            while [[ ${#pids[@]} -ge thread_count ]]; do
                local alive=()
                local pid
                for pid in "${pids[@]}"; do
                    if kill -0 "$pid" 2>/dev/null; then
                        alive+=("$pid")
                    else
                        wait "$pid" 2>/dev/null || log "WARN" "Batch process $pid exited with error"
                    fi
                done
                pids=("${alive[@]}")
                [[ ${#pids[@]} -ge thread_count ]] && sleep 0.1
            done

            scanned=$((scanned + ${#batch_to_scan[@]}))
            [[ "$PROGRESS" == "true" ]] && show_progress_bar "$scanned" "$file_count"
        fi
    done

    # Wait for remaining batches
    if [[ ${#pids[@]} -gt 0 ]]; then
        local pid
        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null || log "WARN" "Final batch process $pid exited with error"
        done
    fi

    [[ "$PROGRESS" == "true" ]] && echo ""
    
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
    log "DEBUG" "Calling output_results"
    output_results "$all_results" "$duration"
    log "DEBUG" "output_results returned"
    
    # Determine exit code
    log "DEBUG" "Calling determine_exit_code"
    determine_exit_code "$all_results"
    log "DEBUG" "determine_exit_code returned"
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
    
    # Validate project root
    if [[ ! -d "$PROJECT_ROOT" ]]; then
        echo -e "${RED}Error: Directory not found: $PROJECT_ROOT${NC}" >&2
        exit 255
    fi
    
    # Print banner
    if [[ " ${OUTPUT_FORMATS[*]} " =~ " console " ]]; then
        print_banner
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
        [[ "$GIT_HISTORY" == "true" ]] && echo -e "${CYAN}Git History:${NC} Enabled"
        [[ "$INCREMENTAL" == "true" ]] && echo -e "${CYAN}Incremental:${NC} Enabled"
        echo ""
    fi
    
    # Run scan
    run_scan
}

# Handle interrupts
trap 'echo -e "\n${YELLOW}Scan interrupted${NC}"; exit 130' INT TERM

# Run
main "$@"