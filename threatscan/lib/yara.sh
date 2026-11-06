#!/usr/bin/env bash
# YARA integration for Advanced Webshell Scanner

# ============================================================================
# YARA COMPILATION
# ============================================================================
compile_yara_rules() {
    local rules_dirs=("$@")
    local output_file="${COMPILE_YARA_OUTPUT:-}"
    [[ -z "$output_file" ]] && output_file=$(make_temp_file).yarc
    
    log "INFO" "Compiling YARA rules from: ${rules_dirs[*]}"
    
    local rule_files=()
    for dir in "${rules_dirs[@]}"; do
        [[ -d "$dir" ]] || { log "WARN" "YARA rules directory not found: $dir"; continue; }
        while IFS= read -r -d '' file; do
            rule_files+=("$file")
        done < <(find "$dir" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 2>/dev/null)
    done
    
    # Add built-in rules
    [[ -d "${RULES_DIR}/yara" ]] && {
        while IFS= read -r -d '' file; do
            rule_files+=("$file")
        done < <(find "${RULES_DIR}/yara" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 2>/dev/null)
    }
    
    # Add custom rules
    [[ -n "$CUSTOM_RULES_DIR" && -d "$CUSTOM_RULES_DIR" ]] && {
        while IFS= read -r -d '' file; do
            rule_files+=("$file")
        done < <(find "$CUSTOM_RULES_DIR" -type f \( -name "*.yar" -o -name "*.yara" -o -name "*.yaml" -o -name "*.yml" \) -print0 2>/dev/null)
    }
    
    # Nothing supplied but yara is available: use the bundled rules so the
    # request does not silently disable YARA detection.
    if [[ ${#rule_files[@]} -eq 0 ]] && command -v yara >/dev/null 2>&1; then
        generate_builtin_yara_rules >/dev/null 2>&1 || true
        while IFS= read -r -d '' file; do
            rule_files+=("$file")
        done < <(find "${RULES_DIR}/yara" -type f \( -name "*.yar" -o -name "*.yara" \) -print0 2>/dev/null)
    fi

    if [[ ${#rule_files[@]} -eq 0 ]]; then
        log "WARN" "No YARA rule files found"
        echo ""
        return 0
    fi
    
    log "INFO" "Found ${#rule_files[@]} YARA rule files"
    
    if command -v yarac >/dev/null 2>&1; then
        # Compile with yarac
        if yarac "${rule_files[@]}" "$output_file" 2>>"$LOG_FILE"; then
            log "INFO" "YARA rules compiled to: $output_file"
            echo "$output_file"
            return 0
        else
            log "ERROR" "YARA compilation failed"
            return 4
        fi
    else
        # No yarac, create a simple index file for yara command
        local index_file="${output_file}.index"
        printf '%s\n' "${rule_files[@]}" > "$index_file"
        log "INFO" "YARA rule index created: $index_file (yarac not available)"
        echo "$index_file"
        return 0
    fi
}

# ============================================================================
# YARA SCANNING
# ============================================================================
scan_with_yara() {
    local file="$1"
    local compiled_rules="$2"
    [[ -z "$compiled_rules" ]] && return 1
    
    local output=""
    if [[ "$compiled_rules" == *.index ]]; then
        # No yarac available: scan once per rule file listed in the index
        local rule_file
        while IFS= read -r rule_file; do
            [[ -f "$rule_file" ]] || continue
            local one
            one=$(yara -w "$rule_file" "$file" 2>/dev/null || true)
            [[ -n "$one" ]] && output+="$one"$'\n'
        done < "$compiled_rules"
    else
        # Compiled .yarc, or a single rule file
        output=$(yara -w "$compiled_rules" "$file" 2>/dev/null || true)
    fi
    
    [[ -z "$output" ]] && return 1
    
    # Parse output: rule namespace:rule_name filepath
    local matches=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local rule_name
        rule_name=$(echo "$line" | awk '{print $1}')
        matches+=("$rule_name")
    done <<< "$output"
    
    printf '%s\n' "${matches[@]}"
    return 0
}

# ============================================================================
# BUILT-IN YARA RULES GENERATION
# ============================================================================
generate_builtin_yara_rules() {
    local output_dir="${RULES_DIR}/yara"
    mkdir -p "$output_dir"
    
    cat > "${output_dir}/php_webshells.yar" << 'YARAEOF'
/*
 * PHP Webshell Detection Rules
 * Generated for Advanced Webshell Scanner
 */

rule php_webshell_c99 {
    meta:
        description = "c99 PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "c99shell"
    strings:
        $s1 = "c99shell" nocase
        $s2 = "C99Shell" nocase
        $s3 = "c99unbound" nocase
        $s4 = "uname -a" nocase
        $s5 = "Safe Mode" nocase
    condition:
        any of them
}

rule php_webshell_r57 {
    meta:
        description = "r57 PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "r57shell"
    strings:
        $s1 = "r57shell" nocase
        $s2 = "R57Shell" nocase
        $s3 = "r57_unbound" nocase
        $s4 = "Safe Mode:" nocase
        $s5 = "disable_functions" nocase
    condition:
        any of them
}

rule php_webshell_wso {
    meta:
        description = "WSO (Web Shell by oRb) PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "wso"
    strings:
        $s1 = "WSO" nocase
        $s2 = "Web Shell by oRb" nocase
        $s3 = "wso.php" nocase
        $s4 = "eval(gzinflate" nocase
        $s5 = "base64_decode" nocase
    condition:
        any of them
}

rule php_webshell_b374k {
    meta:
        description = "b374k PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "b374k"
    strings:
        $s1 = "b374k" nocase
        $s2 = "b374k-shell" nocase
        $s3 = "b374k.php" nocase
    condition:
        any of them
}

rule php_webshell_alphashell {
    meta:
        description = "Alpha Shell PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "alphashell"
    strings:
        $s1 = "Alpha Shell" nocase
        $s2 = "alphashell" nocase
    condition:
        any of them
}

rule php_webshell_indoxploit {
    meta:
        description = "IndoXploit PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "indoxploit"
    strings:
        $s1 = "IndoXploit" nocase
        $s2 = "indoxploit" nocase
        $s3 = "IDXShell" nocase
    condition:
        any of them
}

rule php_webshell_p0wny {
    meta:
        description = "P0wny PHP webshell"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "p0wny"
    strings:
        $s1 = "P0wny" nocase
        $s2 = "p0wny-shell" nocase
    condition:
        any of them
}

rule php_generic_backdoor {
    meta:
        description = "Generic PHP backdoor patterns"
        author = "Webshell Scanner"
        severity = "HIGH"
        family = "generic"
    strings:
        $s1 = "backdoor" nocase
        $s2 = "webshell" nocase
        $s3 = "shell_exec" nocase
        $s4 = "passthru" nocase
        $s5 = "proc_open" nocase
    condition:
        2 of them
}

rule php_obfuscated_eval {
    meta:
        description = "Obfuscated eval patterns"
        author = "Webshell Scanner"
        severity = "HIGH"
        family = "obfuscation"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "eval(gzinflate" nocase
        $s3 = "eval(gzuncompress" nocase
        $s4 = "eval(str_rot13" nocase
        $s5 = "create_function" nocase
        $s6 = "assert(" nocase
    condition:
        any of them
}

rule php_rce_user_input {
    meta:
        description = "RCE via user input"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "rce"
    strings:
        $get = "$_GET"
        $post = "$_POST"
        $request = "$_REQUEST"
        $cookie = "$_COOKIE"
        $server = "$_SERVER"
        $exec = "exec("
        $system = "system("
        $shell = "shell_exec("
        $passthru = "passthru("
        $proc = "proc_open("
        $popen = "popen("
    condition:
        (any of ($get, $post, $request, $cookie, $server)) and
        (any of ($exec, $system, $shell, $passthru, $proc, $popen))
}

rule php_rfi_lfi {
    meta:
        description = "Remote/Local File Inclusion"
        author = "Webshell Scanner"
        severity = "CRITICAL"
        family = "inclusion"
    strings:
        $include = "include("
        $require = "require("
        $include_once = "include_once("
        $require_once = "require_once("
        $get = "$_GET"
        $post = "$_POST"
        $request = "$_REQUEST"
        $cookie = "$_COOKIE"
    condition:
        (any of ($include, $require, $include_once, $require_once)) and
        (any of ($get, $post, $request, $cookie))
}

rule php_suspicious_upload {
    meta:
        description = "Suspicious file upload handling"
        author = "Webshell Scanner"
        severity = "HIGH"
        family = "upload"
    strings:
        $move = "move_uploaded_file("
        $files = "$_FILES"
        $tmp = "tmp_name"
        $php_ext = ".php" nocase
        $phtml_ext = ".phtml" nocase
    condition:
        $move and $files and ($php_ext or $phtml_ext)
}

rule php_high_entropy_payload {
    meta:
        description = "High entropy base64 payload"
        author = "Webshell Scanner"
        severity = "MEDIUM"
        family = "payload"
    strings:
        $b64long = /[A-Za-z0-9+\/]{300,}={0,2}/
    condition:
        $b64long
}

rule php_anonymous_function_abuse {
    meta:
        description = "Anonymous function abuse for obfuscation"
        author = "Webshell Scanner"
        severity = "MEDIUM"
        family = "obfuscation"
    strings:
        $fn = "function("
        $eval = "eval("
        $create = "create_function("
    condition:
        ($fn and $eval) or $create
}
YARAEOF
    
    log "INFO" "Built-in YARA rules generated at ${output_dir}/php_webshells.yar"
}