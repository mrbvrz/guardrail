#!/usr/bin/env bash
# Batch scanning logic for Advanced Webshell Scanner
# Every batch writes one JSON file into a private directory; aggregation happens
# in the parent process so parallel batches never interleave output.

# ============================================================================
# BATCH TRACKING (parent process)
# ============================================================================
# One entry per in-flight batch, so progress reports files that have actually
# been scanned instead of files that were merely handed to a child.
BATCH_PIDS=()
BATCH_DIR=""
BATCH_COMPLETED=0
BATCH_TOTAL=0
BATCH_START_MS=0

# Files finished so far. Each child appends one byte to progress.count after a
# file, so the bar moves file by file instead of jumping once per batch (with
# BATCH_SIZE=100 a batch can run for minutes, which looks like a hang).
batch_progress_count() {
    local dir="${BATCH_DIR:-}"
    local raw
    [[ -z "$dir" ]] && { echo 0; return 0; }
    # progress.count does not exist until the first file finishes; a plain
    # `2>/dev/null` would still let the shell print the redirect error.
    raw=$({ wc -c < "${dir}/progress.count"; } 2>/dev/null) || raw=0
    raw=${raw//[!0-9]/}
    echo "${raw:-0}"
    return 0
}

reap_batches() {
    local alive=()
    local i pid
    for i in "${!BATCH_PIDS[@]}"; do
        pid="${BATCH_PIDS[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
            alive+=("$pid")
        else
            wait "$pid" 2>/dev/null || log "WARN" "Batch process $pid exited with error"
        fi
    done
    if [[ ${#alive[@]} -gt 0 ]]; then
        BATCH_PIDS=("${alive[@]}")
    else
        BATCH_PIDS=()
    fi
    return 0
}

# Block until fewer than $1 batches are in flight. Sleeps in short steps so the
# progress line keeps moving while a slow batch runs (a 100-file batch on a
# large webroot can take minutes, and that must not look like a hang).
drain_batches_to() {
    local limit="${1:-1}"
    while [[ ${#BATCH_PIDS[@]} -ge $limit ]]; do
        reap_batches
        if [[ ${#BATCH_PIDS[@]} -ge $limit ]]; then
            sleep 0.2
            BATCH_COMPLETED=$(batch_progress_count)
            show_progress_bar "$BATCH_COMPLETED" "$BATCH_TOTAL" "$BATCH_START_MS"
        fi
    done
    return 0
}

# Wait for every in-flight batch to finish, repainting progress meanwhile.
drain_batches() {
    while [[ ${#BATCH_PIDS[@]} -gt 0 ]]; do
        reap_batches
        BATCH_COMPLETED=$(batch_progress_count)
        show_progress_bar "$BATCH_COMPLETED" "$BATCH_TOTAL" "$BATCH_START_MS"
        if [[ ${#BATCH_PIDS[@]} -gt 0 ]]; then
            sleep 0.2
        fi
    done
    return 0
}

# ============================================================================
# BATCH PROCESSING
# ============================================================================
# A scanner result is reported as a finding unless it was scored CLEAN.
is_finding() {
    [[ "$1" =~ \"severity\":[[:space:]]*\"CLEAN\" ]] && return 1
    return 0
}

# Heuristic scores below the threshold are noise and do not contribute.
apply_heuristic_threshold() {
    local score="$1" threshold="${2:-0}"
    [[ "$score" =~ ^[0-9]+$ ]] || score=0
    [[ "$threshold" =~ ^[0-9]+$ ]] || threshold=0
    if [[ $score -lt $threshold ]]; then
        score=0
    fi
    echo "$score"
}

scan_batch() {
    local batch_dir="$1"
    local yara_compiled="$2"
    local scan_id="$3"
    shift 3
    local batch_files=("$@")

    local batch_results=()
    local out_file="${batch_dir}/batch-$$-${RANDOM}.json"

    for file in "${batch_files[@]}"; do
        [[ -n "$file" ]] || continue
        local result=""
        local ret=0
        local err_file
        err_file=$(mktemp)

        if result=$(scan_single_file "$file" "$yara_compiled" "$scan_id" 2>"$err_file"); then
            ret=0
        else
            ret=$?
        fi

        if [[ -s "$err_file" ]]; then
            log "WARN" "scan_single_file error for $file: $(cat "$err_file")"
        fi
        rm -f "$err_file"

        if [[ $ret -ne 0 ]]; then
            log "WARN" "scan_single_file exited with code $ret for $file"
        fi

        # Only non-clean results are findings. Clean files are accounted for by
        # scan_info.total_files; emitting them inflates findings and makes
        # SARIF/JUnit consumers report thousands of non-issues.
        if [[ -n "$result" ]] && is_finding "$result"; then
            batch_results+=("$result")
        fi
        # One byte per finished file: the parent reads this to drive progress.
        printf '.' >> "${batch_dir}/progress.count" 2>/dev/null || true
    done

    if [[ ${#batch_results[@]} -gt 0 ]]; then
        if ! printf '%s\n' "${batch_results[@]}" | jq -s '.' > "$out_file" 2>>"$LOG_FILE"; then
            log "ERROR" "Failed to serialise batch results (${#batch_results[@]} files)"
            rm -f "$out_file"
            return 1
        fi
    else
        log "DEBUG" "scan_batch: no results for batch"
    fi

    return 0
}

# ============================================================================
# SINGLE FILE SCAN
# ============================================================================
scan_single_file() {
    local file="$1"
    local yara_compiled="$2"
    local scan_id="$3"

    local rel_file="${file#$PROJECT_ROOT/}"
    local start_time
    start_time=$(timestamp_ms)

    # Read content
    local content
    content=$(cat "$file" 2>/dev/null) || content=""
    [[ -z "$content" ]] && return 0

    local file_size
    file_size=$(get_file_size "$file")
    local file_hash
    file_hash=$(get_file_hash "$file")

    # Check cache
    local cache_key=""
    if [[ "$INCREMENTAL" == "true" && -n "$CACHE_DIR" ]]; then
        cache_key=$(get_file_cache_key "$file")
        local cached
        cached=$(check_cache "$cache_key")
        if [[ -n "$cached" ]]; then
            log "DEBUG" "Cache hit: $rel_file"
            echo "$cached"
            return 0
        fi
    fi

    # Initialize finding object
    local finding_json
    finding_json=$(jq -n \
        --arg file "$rel_file" \
        --arg hash "$file_hash" \
        --argjson size "${file_size:-0}" \
        '{file: $file, hash: $hash, size: $size}')

    # Signature detection (from basic scanner)
    local sig_results
    sig_results=$(run_signature_detection "$content" "$rel_file")
    finding_json=$(echo "$finding_json" | jq --argjson sig "${sig_results:-[]}" '. + {signatures: $sig}')

    # YARA scanning
    local yara_matches=()
    if [[ -n "$yara_compiled" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && yara_matches+=("$line")
        done < <(scan_with_yara "$file" "$yara_compiled")
    fi
    local yara_json="[]"
    if [[ ${#yara_matches[@]} -gt 0 ]]; then
        yara_json=$(json_array_from_list "$(printf '%s|' "${yara_matches[@]}")")
    fi
    finding_json=$(echo "$finding_json" | jq --argjson yara "$yara_json" '. + {yara_matches: $yara}')

    # Entropy analysis
    local overall_entropy=0 max_entropy=0 b64_max_entropy=0 sections_json="[]"
    if [[ "${SIGNATURES_ONLY:-false}" != "true" && "${QUICK_MODE:-false}" != "true" ]]; then
        local entropy_results
        entropy_results=$(scan_entropy "$file" 2>/dev/null) || entropy_results="0.0000|0.0000|0.0000|[]"
        IFS='|' read -r overall_entropy max_entropy b64_max_entropy sections_json <<< "$entropy_results"
        overall_entropy="${overall_entropy:-0}"
        max_entropy="${max_entropy:-0}"
        b64_max_entropy="${b64_max_entropy:-0}"
        sections_json="${sections_json:-[]}"
        [[ "$sections_json" == \[*\] ]] || sections_json="[]"
    fi

    finding_json=$(echo "$finding_json" | jq \
        --argjson overall "$overall_entropy" \
        --argjson max "$max_entropy" \
        --argjson b64 "$b64_max_entropy" \
        --argjson sections "$sections_json" \
        '. + {entropy: {overall: $overall, max: $max, b64_max: $b64, sections: $sections}}')

    # Heuristic analysis
    local heur_json='{"score":0,"signals":{}}'
    if [[ "${SIGNATURES_ONLY:-false}" != "true" ]]; then
        heur_json=$(analyze_heuristics "$file")
        [[ -z "$heur_json" ]] && heur_json='{"score":0,"signals":{}}'
    fi
    finding_json=$(echo "$finding_json" | jq --argjson heur "$heur_json" \
        '. + {heuristics: $heur.signals, heuristic_score: $heur.score}')

    # Calculate final score
    local base_score
    base_score=$(echo "$finding_json" | jq -r '.heuristic_score // 0')

    # Boost for YARA matches
    local yara_count
    yara_count=$(echo "$finding_json" | jq '.yara_matches | length')
    local yara_bonus=$((yara_count * $(heuristic_weight "yara_bonus")))

    # Boost for critical signatures
    local sig_count
    sig_count=$(echo "$finding_json" | jq '.signatures | length')
    local sig_bonus=$((sig_count * 20))

    # Boost for high entropy
    local entropy_bonus=0
    if float_gt "$max_entropy" 7.5; then
        entropy_bonus=20
    elif float_gt "$max_entropy" 7.0; then
        entropy_bonus=10
    fi

    local final_score=$((base_score + yara_bonus + sig_bonus + entropy_bonus))
    # The threshold only silences pure heuristic noise; a real signature, YARA
    # match or high-entropy block must never be hidden by a low score.
    if [[ $yara_count -eq 0 && $sig_count -eq 0 && $entropy_bonus -eq 0 ]]; then
        final_score=$(apply_heuristic_threshold "$final_score" "${HEURISTIC_THRESHOLD:-0}")
    fi
    [[ $final_score -gt 100 ]] && final_score=100

    local severity
    severity=$(severity_from_score "$final_score")

    finding_json=$(echo "$finding_json" | jq \
        --argjson score "$final_score" \
        --arg severity "$severity" \
        '. + {score: $score, severity: $severity}')

    # Quarantine if needed
    if [[ -n "$QUARANTINE_DIR" ]] && should_quarantine "$severity"; then
        local reason="Score: $final_score, Severity: $severity"
        [[ ${#yara_matches[@]} -gt 0 ]] && reason+=", YARA: ${yara_matches[*]}"
        quarantine_file "$file" "$severity" "$reason" "$scan_id" >/dev/null
        finding_json=$(echo "$finding_json" | jq '. + {quarantined: true}')
    fi

    # Scan duration
    local duration=$(( $(timestamp_ms) - start_time ))
    finding_json=$(echo "$finding_json" | jq --argjson dur "$duration" '. + {scan_duration_ms: $dur}')

    # Output
    echo "$finding_json"

    # Cache
    if [[ "$INCREMENTAL" == "true" && -n "$CACHE_DIR" && -n "$cache_key" ]]; then
        write_cache "$cache_key" "$finding_json"
    fi

    log "DEBUG" "Scanned: $rel_file (Score: $final_score, Severity: $severity, Duration: ${duration}ms)"
    return 0
}

# ============================================================================
# SIGNATURE DETECTION (from basic scanner)
# ============================================================================
run_signature_detection() {
    local content="$1"
    local file="$2"
    local results=()

    # A function name mentioned in a comment is documentation, not code.
    content=$(printf '%s\n' "$content" | strip_source_comments)

    # Known webshell signatures
    local webshell_names=(
        "c99shell" "r57shell" "wso" "b374k" "alpha_shell" "c100" "madspot"
        "indoxploit" "kalihack" "shellbot" "p0wny" "mini_shell" "simple_shell"
        "webconsole" "phpshell" "backdoor" "webshell"
    )
    local webshell_patterns=(
        "c99shell|C99Shell|c99unbound|C99Unbound"
        "r57shell|R57Shell|r57_unbound"
        "WSO|wso|Web Shell by oRb"
        "b374k|B374K|b374k-shell"
        "Alpha Shell|alphashell|AlphaShell"
        "c100shell|C100Shell"
        "MadSpot|madspot"
        "IndoXploit|indoxploit|IDXShell"
        "Kali Hack|kalihack"
        "ShellBot|shellbot"
        "P0wny|p0wny|p0wny-shell"
        "Mini Shell|mini-shell|mini_shell"
        "Simple Shell|simple-shell"
        "Web Console|webconsole|web-console"
        "PHP Shell|PHPshell|php-shell"
        "backdoor|Backdoor|BACKDOOR"
        "webshell|Webshell|WEB SHELL"
    )

    local i
    for i in "${!webshell_names[@]}"; do
        if echo "$content" | grep -qiE "${webshell_patterns[$i]}"; then
            results+=("{\"type\":\"known_webshell\",\"name\":\"${webshell_names[$i]}\",\"severity\":\"CRITICAL\"}")
        fi
    done

    # Dangerous functions with user input
    local dangerous_funcs=(
        "eval" "exec" "system" "shell_exec" "passthru" "proc_open" "popen"
        "pcntl_exec" "assert" "create_function" "call_user_func" "call_user_func_array"
        "array_map" "array_filter" "array_walk" "preg_replace" "mb_ereg_replace"
        "base64_decode" "gzuncompress" "gzinflate" "gzdecode" "str_rot13" "hex2bin"
    )

    local func
    for func in "${dangerous_funcs[@]}"; do
        if echo "$content" | grep -qE "${func}[[:space:]]*\([[:space:]]*\\\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)"; then
            results+=("{\"type\":\"dangerous_function_user_input\",\"function\":\"$func\",\"severity\":\"HIGH\"}")
        fi
    done

    # Obfuscation patterns
    local obfuscation_patterns=(
        "eval[[:space:]]*\([[:space:]]*base64_decode"
        "eval[[:space:]]*\([[:space:]]*gzinflate"
        "eval[[:space:]]*\([[:space:]]*gzuncompress"
        "eval[[:space:]]*\([[:space:]]*gzdecode"
        "eval[[:space:]]*\([[:space:]]*str_rot13"
        "eval[[:space:]]*\([[:space:]]*hex2bin"
        "create_function[[:space:]]*\([[:space:]]*base64_decode"
        "assert[[:space:]]*\([[:space:]]*base64_decode"
        "preg_replace[[:space:]]*\(.*\/e"
    )

    local pattern
    for pattern in "${obfuscation_patterns[@]}"; do
        if echo "$content" | grep -qE "$pattern"; then
            results+=("{\"type\":\"obfuscation\",\"pattern\":\"$(json_escape "$pattern")\",\"severity\":\"HIGH\"}")
        fi
    done

    # Command execution
    if echo "$content" | grep -qE '\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)[[:space:]]*\[[[:space:]]*["'"'"'](cmd|command|exec|shell|system|run)["'"'"'][[:space:]]*\]'; then
        results+=("{\"type\":\"command_execution\",\"severity\":\"CRITICAL\"}")
    fi

    # File inclusion
    if echo "$content" | grep -qE '(include|require|include_once|require_once)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'; then
        results+=("{\"type\":\"file_inclusion\",\"severity\":\"CRITICAL\"}")
    fi

    # Suspicious filename
    local basename_file
    basename_file=$(basename "$file")
    local basename_lower
    basename_lower=$(echo "$basename_file" | tr '[:upper:]' '[:lower:]')
    local suspicious_names=(
        "shell.php" "cmd.php" "command.php" "exec.php" "backdoor.php" "webshell.php"
        "r57.php" "c99.php" "wso.php" "b374k.php" "config.php.bak" "config.php.backup"
        "test.php" "info.php" "phpinfo.php" "uploader.php" "filemanager.php" "adminer.php"
    )

    local sus
    for sus in "${suspicious_names[@]}"; do
        if [[ "$basename_lower" == "$sus" ]]; then
            results+=("{\"type\":\"suspicious_filename\",\"name\":\"$basename_file\",\"severity\":\"CRITICAL\"}")
        fi
    done

    # Dangerous .htaccess / .user.ini directives
    if [[ "$basename_lower" == ".htaccess" || "$basename_lower" == ".user.ini" ]]; then
        if echo "$content" | grep -qiE '(auto_prepend_file|auto_append_file|allow_url_include|SetHandler.*application/x-httpd-php|AddType.*application/x-httpd-php|AddHandler.*application/x-httpd-php)'; then
            results+=("{\"type\":\"malicious_config_directive\",\"file\":\"$basename_file\",\"severity\":\"CRITICAL\"}")
        fi
    fi

    # Double extension disguised executable (e.g. avatar.php.jpg, shell.phtml.png)
    case "$basename_lower" in
        *.php.*|*.phtml.*|*.phar.*|*.shtml.*)
            results+=("{\"type\":\"double_extension_webshell\",\"name\":\"$basename_file\",\"severity\":\"HIGH\"}")
            ;;
    esac

    # Output as JSON array
    if [[ ${#results[@]} -eq 0 ]]; then
        echo "[]"
        return 0
    fi
    printf '%s\n' "${results[@]}" | jq -s '.'
}
