#!/usr/bin/env bash
# Heuristic scoring engine for Advanced Webshell Scanner

# ============================================================================
# HEURISTIC WEIGHTS (configurable)
# ============================================================================
HEURISTIC_WEIGHT_dangerous_functions=15
HEURISTIC_WEIGHT_obfuscation=20
HEURISTIC_WEIGHT_user_input_sinks=25
HEURISTIC_WEIGHT_file_operations=15
HEURISTIC_WEIGHT_network_operations=10
HEURISTIC_WEIGHT_suspicious_strings=10
HEURISTIC_WEIGHT_entropy=5
HEURISTIC_WEIGHT_yara_bonus=30

heuristic_weight() {
    local var="HEURISTIC_WEIGHT_$1"
    local val
    val="${!var-}"
    printf '%s' "${val:-0}"
}

# Signal names for iteration
HEURISTIC_SIGNALS=("dangerous_functions" "obfuscation" "user_input_sinks" "file_operations" "network_operations" "suspicious_strings" "entropy" "yara_bonus")

# Count all matches of any pattern in a single grep pass.
grep_count_any() {
    local ignore_case=false
    if [[ "${1:-}" == "-i" ]]; then
        ignore_case=true
        shift
    fi
    local content="$1"
    shift
    local re="" p
    for p in "$@"; do
        [[ -n "$re" ]] && re+="|"
        re+="($p)"
    done
    local count
    if [[ "$ignore_case" == "true" ]]; then
        count=$(printf '%s\n' "$content" | grep -oiE "$re" 2>/dev/null | wc -l)
    else
        count=$(printf '%s\n' "$content" | grep -oE "$re" 2>/dev/null | wc -l)
    fi
    echo $((count + 0))
}

# Drop comment-only lines before scoring. Scanned files are untrusted: a
# function name mentioned in documentation is not executable code.
strip_source_comments() {
    grep -vE '^[[:space:]]*(//|#|\*|/\*|<!--|-->|\*/)' 2>/dev/null || true
}

# ============================================================================
# HEURISTIC ANALYSIS
# ============================================================================
analyze_heuristics() {
    local file="$1"
    local content
    content=$(cat "$file" 2>/dev/null)
    [[ -z "$content" ]] && output_heuristic_zero && return
    content=$(printf '%s\n' "$content" | strip_source_comments)
    [[ -z "$content" ]] && output_heuristic_zero && return
    
    # Use regular arrays for bash 3.x compatibility
    local signals_dangerous_functions=$(count_dangerous_functions "$content")
    local signals_obfuscation=$(count_obfuscation "$content")
    local signals_user_input_sinks=$(count_user_input_sinks "$content")
    local signals_file_operations=$(count_file_operations "$content")
    local signals_network_operations=$(count_network_operations "$content")
    local signals_suspicious_strings=$(count_suspicious_strings "$content")
    local signals_entropy=0
    local details_entropy=""
    
    # Details are only collected for signals that actually fired, so clean
    # files stay at one grep per category instead of one per pattern.
    local details_dangerous_functions="" details_obfuscation=""
    local details_user_input_sinks="" details_file_operations=""
    local details_network_operations="" details_suspicious_strings=""
    [[ $signals_dangerous_functions -gt 0 ]] && details_dangerous_functions=$(list_dangerous_functions "$content")
    [[ $signals_obfuscation -gt 0 ]] && details_obfuscation=$(list_obfuscation "$content")
    [[ $signals_user_input_sinks -gt 0 ]] && details_user_input_sinks=$(list_user_input_sinks "$content")
    [[ $signals_file_operations -gt 0 ]] && details_file_operations=$(list_file_operations "$content")
    [[ $signals_network_operations -gt 0 ]] && details_network_operations=$(list_network_operations "$content")
    [[ $signals_suspicious_strings -gt 0 ]] && details_suspicious_strings=$(list_suspicious_strings "$content")
    
    # Calculate weighted score
    local score=0
    score=$((score + signals_dangerous_functions * $(heuristic_weight "dangerous_functions")))
    score=$((score + signals_obfuscation * $(heuristic_weight "obfuscation")))
    score=$((score + signals_user_input_sinks * $(heuristic_weight "user_input_sinks")))
    score=$((score + signals_file_operations * $(heuristic_weight "file_operations")))
    score=$((score + signals_network_operations * $(heuristic_weight "network_operations")))
    score=$((score + signals_suspicious_strings * $(heuristic_weight "suspicious_strings")))
    score=$((score + signals_entropy * $(heuristic_weight "entropy")))
    
    # Cap at 100
    [[ $score -gt 100 ]] && score=100
    
    # Output JSON
    local json="{"
    json+="\"score\":$score,"
    json+="\"severity\":\"$(severity_from_score "$score")\","
    json+="\"signals\":{"
    json+="\"dangerous_functions\":{\"count\":$signals_dangerous_functions,\"weight\":$(heuristic_weight "dangerous_functions"),\"details\":$(json_escape_array "$details_dangerous_functions")},"
    json+="\"obfuscation\":{\"count\":$signals_obfuscation,\"weight\":$(heuristic_weight "obfuscation"),\"details\":$(json_escape_array "$details_obfuscation")},"
    json+="\"user_input_sinks\":{\"count\":$signals_user_input_sinks,\"weight\":$(heuristic_weight "user_input_sinks"),\"details\":$(json_escape_array "$details_user_input_sinks")},"
    json+="\"file_operations\":{\"count\":$signals_file_operations,\"weight\":$(heuristic_weight "file_operations"),\"details\":$(json_escape_array "$details_file_operations")},"
    json+="\"network_operations\":{\"count\":$signals_network_operations,\"weight\":$(heuristic_weight "network_operations"),\"details\":$(json_escape_array "$details_network_operations")},"
    json+="\"suspicious_strings\":{\"count\":$signals_suspicious_strings,\"weight\":$(heuristic_weight "suspicious_strings"),\"details\":$(json_escape_array "$details_suspicious_strings")},"
    json+="\"entropy\":{\"count\":$signals_entropy,\"weight\":$(heuristic_weight "entropy"),\"details\":$(json_escape_array "$details_entropy")},"
    json+="\"yara_bonus\":{\"count\":0,\"weight\":$(heuristic_weight "yara_bonus"),\"details\":[]}"
    json+="}}"
    echo "$json"
}

output_heuristic_zero() {
    local json="{"
    json+="\"score\":0,"
    json+="\"severity\":\"CLEAN\","
    json+="\"signals\":{"
    local first=true
    for signal in "${HEURISTIC_SIGNALS[@]}"; do
        [[ "$first" == "true" ]] && first=false || json+=","
        json+="\"$signal\":{\"count\":0,\"weight\":$(heuristic_weight "$signal"),\"details\":[]}"
    done
    json="${json%,}"
    json+="}}"
    echo "$json"
}

json_escape_array() {
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
# SIGNAL DETECTION FUNCTIONS
# ============================================================================

count_dangerous_functions() {
    local content="$1"
    local patterns=(
        '\beval\s*\('
        '\bexec\s*\('
        '\bsystem\s*\('
        '\bshell_exec\s*\('
        '\bpassthru\s*\('
        '\bproc_open\s*\('
        '\bpopen\s*\('
        '\bpcntl_exec\s*\('
        '\bassert\s*\('
        '\bcreate_function\s*\('
        '\bcall_user_func\s*\('
        '\bcall_user_func_array\s*\('
        '\bpreg_replace\s*\('
    )
    grep_count_any "$content" "${patterns[@]}"
}

list_dangerous_functions() {
    local content="$1"
    local patterns=(
        'eval:eval\s*\('
        'exec:exec\s*\('
        'system:system\s*\('
        'shell_exec:shell_exec\s*\('
        'passthru:passthru\s*\('
        'proc_open:proc_open\s*\('
        'popen:popen\s*\('
        'pcntl_exec:pcntl_exec\s*\('
        'assert:assert\s*\('
        'create_function:create_function\s*\('
        'call_user_func:call_user_func\s*\('
        'call_user_func_array:call_user_func_array\s*\('
        'preg_replace:preg_replace\s*\('
    )
    local results=()
    for p in "${patterns[@]}"; do
        local name="${p%%:*}"
        local pattern="${p#*:}"
        local matches
        matches=$(echo "$content" | grep -oE "$pattern" | wc -l | tr -d '[:space:]')
        [[ $matches -gt 0 ]] && results+=("$name:$matches")
    done
    local IFS='|'
    echo "${results[*]:-}"
}

count_obfuscation() {
    local content="$1"
    local patterns=(
        'eval\s*\(\s*base64_decode'
        'eval\s*\(\s*gzinflate'
        'eval\s*\(\s*gzuncompress'
        'eval\s*\(\s*gzdecode'
        'eval\s*\(\s*str_rot13'
        'eval\s*\(\s*hex2bin'
        'create_function\s*\(\s*base64_decode'
        'assert\s*\(\s*base64_decode'
        'preg_replace\s*\(.*\/e'
        'gzinflate\s*\(\s*base64_decode'
        'gzuncompress\s*\(\s*base64_decode'
        'str_rot13\s*\(\s*base64_decode'
        '\$_[A-Z]+\s*\[\s*['"'"'\"].*['"'"'\"]\s*\]\s*\(\s*base64_decode'
    )
    grep_count_any "$content" "${patterns[@]}"
}

list_obfuscation() {
    local content="$1"
    local patterns=(
        'eval_base64:eval\s*\(\s*base64_decode'
        'eval_gzinflate:eval\s*\(\s*gzinflate'
        'eval_gzuncompress:eval\s*\(\s*gzuncompress'
        'eval_gzdecode:eval\s*\(\s*gzdecode'
        'eval_rot13:eval\s*\(\s*str_rot13'
        'eval_hex2bin:eval\s*\(\s*hex2bin'
        'cf_base64:create_function\s*\(\s*base64_decode'
        'assert_base64:assert\s*\(\s*base64_decode'
        'preg_replace_e:preg_replace\s*\(.*\/e'
        'gzinflate_base64:gzinflate\s*\(\s*base64_decode'
        'gzuncompress_base64:gzuncompress\s*\(\s*base64_decode'
        'rot13_base64:str_rot13\s*\(\s*base64_decode'
        'superglobal_base64:\$_[A-Z]+\s*\[\s*['"'"'\"].*['"'"'\"]\s*\]\s*\(\s*base64_decode'
    )
    local results=()
    for p in "${patterns[@]}"; do
        local name="${p%%:*}"
        local pattern="${p#*:}"
        local matches
        matches=$(echo "$content" | grep -oE "$pattern" | wc -l | tr -d '[:space:]')
        [[ $matches -gt 0 ]] && results+=("$name:$matches")
    done
    local IFS='|'
    echo "${results[*]:-}"
}

count_user_input_sinks() {
    local content="$1"
    # Direct superglobal to dangerous function
    local patterns=(
        '\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*['"'"'\"].*['"'"'\"]\s*\]\s*\(\s*\)'
        'eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'proc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
    )
    grep_count_any "$content" "${patterns[@]}"
}

list_user_input_sinks() {
    local content="$1"
    local patterns=(
        'eval_superglobal:eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'exec_superglobal:exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'system_superglobal:system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'shell_exec_superglobal:shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'passthru_superglobal:passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'proc_open_superglobal:proc_open\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'popen_superglobal:popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'assert_superglobal:assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
    )
    local results=()
    for p in "${patterns[@]}"; do
        local name="${p%%:*}"
        local pattern="${p#*:}"
        local matches
        matches=$(echo "$content" | grep -oE "$pattern" | wc -l | tr -d '[:space:]')
        [[ $matches -gt 0 ]] && results+=("$name:$matches")
    done
    local IFS='|'
    echo "${results[*]:-}"
}

count_file_operations() {
    local content="$1"
    local patterns=(
        'unlink\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'mkdir\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'rmdir\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'chmod\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'chown\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'copy\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'rename\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'file_put_contents\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'fwrite\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'fputs\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'move_uploaded_file\s*\(\s*\$_(FILES|POST|GET)'
        'include\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'require\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'include_once\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'require_once\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
    )
    grep_count_any "$content" "${patterns[@]}"
}

list_file_operations() {
    local content="$1"
    local patterns=(
        'unlink_superglobal:unlink\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'mkdir_superglobal:mkdir\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'chmod_superglobal:chmod\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'file_put_contents_superglobal:file_put_contents\s*\(\s*\$_(GET|POST|REQUEST|FILES)'
        'move_uploaded_file_superglobal:move_uploaded_file\s*\(\s*\$_(FILES|POST|GET)'
        'include_superglobal:include\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
        'require_superglobal:require\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)'
    )
    local results=()
    for p in "${patterns[@]}"; do
        local name="${p%%:*}"
        local pattern="${p#*:}"
        local matches
        matches=$(echo "$content" | grep -oE "$pattern" | wc -l | tr -d '[:space:]')
        [[ $matches -gt 0 ]] && results+=("$name:$matches")
    done
    local IFS='|'
    echo "${results[*]:-}"
}

count_network_operations() {
    local content="$1"
    local patterns=(
        '\bcurl_init\s*\('
        '\bcurl_exec\s*\('
        '\bfsockopen\s*\('
        '\bpfsockopen\s*\('
        '\bsocket_create\s*\('
        '\bsocket_connect\s*\('
        '\bstream_socket_client\s*\('
        '\bfile_get_contents\s*\(\s*['"'"'\"](https?|ftp)://'
        '\breadfile\s*\(\s*['"'"'\"](https?|ftp)://'
    )
    grep_count_any "$content" "${patterns[@]}"
}

list_network_operations() {
    local content="$1"
    local patterns=(
        'curl:curl_init\s*\('
        'fsockopen:fsockopen\s*\('
        'pfsockopen:pfsockopen\s*\('
        'socket_create:socket_create\s*\('
        'stream_socket_client:stream_socket_client\s*\('
        'file_get_contents_url:file_get_contents\s*\(\s*['"'"'\"](https?|ftp)://'
    )
    local results=()
    for p in "${patterns[@]}"; do
        local name="${p%%:*}"
        local pattern="${p#*:}"
        local matches
        matches=$(echo "$content" | grep -oE "$pattern" | wc -l | tr -d '[:space:]')
        [[ $matches -gt 0 ]] && results+=("$name:$matches")
    done
    local IFS='|'
    echo "${results[*]:-}"
}

count_suspicious_strings() {
    local content="$1"
    local patterns=(
        'shell' 'backdoor' 'rootkit' 'exploit' 'payload' 'c99' 'r57' 'wso'
        'b374k' 'alphashell' 'indoxploit' 'p0wny' 'webconsole' 'phpshell'
        'cmd' 'command' 'exec' 'hacker' 'owned' 'pwned' 'defaced'
        'anonymous' 'lulzsec' 'antisec' 'bypass' 'disable_functions'
        'open_basedir' 'safe_mode' 'suhosin' 'ioncube' 'zend'
    )
    grep_count_any -i "$content" "${patterns[@]}"
}

list_suspicious_strings() {
    local content="$1"
    local patterns=(
        'shell' 'backdoor' 'rootkit' 'exploit' 'payload' 'c99' 'r57' 'wso'
        'b374k' 'alphashell' 'indoxploit' 'p0wny' 'webconsole' 'phpshell'
        'cmd' 'command' 'exec' 'hacker' 'owned' 'pwned' 'defaced'
    )
    local results=()
    for pattern in "${patterns[@]}"; do
        local matches
        matches=$(echo "$content" | grep -io "$pattern" | wc -l | tr -d '[:space:]')
        [[ $matches -gt 0 ]] && results+=("$pattern:$matches")
    done
    local IFS='|'
    echo "${results[*]:-}"
}