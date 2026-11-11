#!/usr/bin/env bash
# Output formatters for Advanced Webshell Scanner

xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&apos;}"
    printf '%s' "$s"
}

# JSON embedded in a <script> block must not be able to close the tag.
json_for_script() {
    local s="$1"
    printf '%s' "${s//</\\u003c}"
}

# ============================================================================
# CONSOLE OUTPUT
# ============================================================================
output_console() {
    local results="$1"
    local duration="${2:-0}"

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}SCAN RESULTS${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""

    local critical high medium low clean
    critical=$(echo "$results" | jq -r '.summary.critical // 0')
    high=$(echo "$results" | jq -r '.summary.high // 0')
    medium=$(echo "$results" | jq -r '.summary.medium // 0')
    low=$(echo "$results" | jq -r '.summary.low // 0')
    clean=$(echo "$results" | jq -r '.summary.clean // 0')
    local total=$((critical + high + medium + low + clean))

    printf "%-10s" "SEVERITY"
    printf "${RED}${BOLD}%-10s${NC}" "CRITICAL"
    printf "${RED}%-10s${NC}" "HIGH"
    printf "${YELLOW}${BOLD}%-10s${NC}" "MEDIUM"
    printf "${YELLOW}%-10s${NC}" "LOW"
    printf "${GREEN}%-10s${NC}\n" "CLEAN"
    printf "%-10s" "COUNT"
    printf "${RED}${BOLD}%-10d${NC}" "$critical"
    printf "${RED}%-10d${NC}" "$high"
    printf "${YELLOW}${BOLD}%-10d${NC}" "$medium"
    printf "${YELLOW}%-10d${NC}" "$low"
    printf "${GREEN}%-10d${NC}\n" "$clean"
    printf "%-10s%d\n\n" "TOTAL" "$total"

    echo -e "${BOLD}TOP FINDINGS:${NC}"
    printf "%-46s %6s %10s %s\n" "FILE" "SCORE" "SEVERITY" "DETAILS"
    printf "%-46s %6s %10s %s\n" "----" "-----" "--------" "-------"

    echo "$results" | jq -r '
        .findings[]? |
        [ (.file // ""),
          ((.score // 0) | tostring),
          (.severity // "CLEAN"),
          ((.yara_matches // []) | join(",")),
          ((.entropy.max // 0) | tostring),
          ([(.heuristics // {} | to_entries[]? | select((.value.count // 0) > 0) | "\(.key)=\(.value.count)")] | join(" "))
        ] | join("\u001f")' | while IFS=$'\x1f' read -r file score severity yara entropy heur; do
        local color
        color=$(color_for_severity "$severity")
        local short_file="$file"
        [[ ${#short_file} -gt 44 ]] && short_file="${short_file:0:42}.."

        local details=""
        [[ -n "$yara" ]] && details+="YARA:[$yara] "
        if float_gt "$entropy" 0; then details+="entropy=$entropy "; fi
        [[ -n "$heur" ]] && details+="$heur"

        printf "${color}%-46s %6s %10s${NC} %s\n" "$short_file" "$score" "$severity" "$details"
    done

    echo ""
    local scanned
    scanned=$(echo "$results" | jq -r '.scan_info.total_files // 0')
    if [[ "$scanned" =~ ^[0-9]+$ ]] && [[ $scanned -gt 0 ]]; then
        local per_sec=""
        if [[ "$duration" =~ ^[0-9]+$ ]] && [[ $duration -gt 0 ]]; then
            per_sec=$(awk -v c="$scanned" -v d="$duration" 'BEGIN { printf " (%.1f files/s)", c * 1000 / d }')
        fi
        echo -e "${CYAN}Files scanned:${NC} ${scanned}${per_sec}"
    fi
    echo -e "${CYAN}Duration:${NC} $(format_duration "$duration")"
    echo -e "${CYAN}Log:${NC} ${LOG_FILE:-n/a}"

    if [[ -n "${QUARANTINE_DIR:-}" ]]; then
        echo -e "${CYAN}Quarantine:${NC} $QUARANTINE_DIR"
    fi

    return 0
}

# ============================================================================
# JSON OUTPUT
# ============================================================================
output_json() {
    local results="$1"
    local duration="${2:-0}"
    mkdir -p "$OUTPUT_DIR"
    local slug_part="${SCAN_TARGET_SLUG:+${SCAN_TARGET_SLUG}-}"
    local output_file="${OUTPUT_DIR}/webshell-scan-${slug_part}$(date +%Y%m%d-%H%M%S).json"

    local enriched_results
    enriched_results=$(echo "$results" | jq --argjson dur "$duration" --arg log "${LOG_FILE:-}" '
        . + {
            "scan_metadata": {
                "duration_ms": $dur,
                "log_file": $log,
                "scanner_version": "2.0",
                "timestamp": (now | strftime("%Y-%m-%dT%H:%M:%S%z"))
            }
        }
    ')

    if [[ -z "$enriched_results" ]]; then
        log "ERROR" "Failed to build JSON report"
        return 1
    fi

    echo "$enriched_results" | jq '.' > "$output_file"
    echo -e "${CYAN}JSON report saved to:${NC} $output_file"
    return 0
}

# ============================================================================
# SARIF OUTPUT (for GitHub Code Scanning)
# ============================================================================
output_sarif() {
    local results="$1"
    local duration="${2:-0}"
    mkdir -p "$OUTPUT_DIR"
    local slug_part="${SCAN_TARGET_SLUG:+${SCAN_TARGET_SLUG}-}"
    local output_file="${OUTPUT_DIR}/webshell-scan-${slug_part}$(date +%Y%m%d-%H%M%S).sarif"

    local sarif_results
    sarif_results=$(echo "$results" | jq -c '
        [ .findings[]? |
          {
            ruleId: "WS002",
            level: (if (.severity == "CRITICAL" or .severity == "HIGH") then "error"
                    elif .severity == "MEDIUM" then "warning"
                    else "note" end),
            message: {
              text: ("\(.severity // "CLEAN") finding (score \(.score // 0))"
                     + (if ((.yara_matches // []) | length) > 0 then ": " + (.yara_matches | join(", ")) else "" end))
            },
            locations: [{
              physicalLocation: {
                artifactLocation: { uri: (.file // "") },
                region: { startLine: 1 }
              }
            }],
            properties: { score: (.score // 0), severity: (.severity // "CLEAN") }
          }
        ]')

    if [[ -z "$sarif_results" ]]; then
        sarif_results='[]'
    fi

    local rules='[]'
    rules=$(echo "$results" | jq -c '
        [ .findings[]? | {id: "WS002", name: "WebshellFinding",
            shortDescription: {text: "Webshell or malicious PHP pattern"},
            defaultConfiguration: {level: "error"}} ] | unique_by(.id)')

    local now
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    jq -n \
        --argjson results "$sarif_results" \
        --argjson rules "$rules" \
        --arg start "$now" \
        --arg end "$now" \
        '{
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: [{
                tool: { driver: {
                    name: "Advanced Webshell Scanner",
                    version: "2.0",
                    informationUri: "https://github.com/security/webshell-scanner",
                    rules: $rules
                }},
                results: $results,
                invocations: [{
                    executionSuccessful: true,
                    startTimeUtc: $start,
                    endTimeUtc: $end
                }]
            }]
        }' > "$output_file"

    echo -e "${CYAN}SARIF report saved to:${NC} $output_file"
    return 0
}

# ============================================================================
# HTML OUTPUT
# ============================================================================
output_html() {
    local results="$1"
    local duration="${2:-0}"

    mkdir -p "$OUTPUT_DIR"
    local slug_part="${SCAN_TARGET_SLUG:+${SCAN_TARGET_SLUG}-}"
    local output_file="${OUTPUT_DIR}/webshell-scan-${slug_part}$(date +%Y%m%d-%H%M%S).html"

    local template="${TEMPLATES_DIR}/dashboard.html"
    if [[ ! -s "$template" ]]; then
        log "ERROR" "HTML template unavailable at ${TEMPLATES_DIR}/dashboard.html"
        echo -e "${RED}HTML report failed: template unavailable${NC}" >&2
        return 1
    fi

    local summary_json findings_json scan_info_json timestamp
    summary_json=$(json_for_script "$(echo "$results" | jq -c '.summary // {}')")
    findings_json=$(json_for_script "$(echo "$results" | jq -c '.findings // []')")
    scan_info_json=$(json_for_script "$(echo "$results" | jq -c '.scan_info // {}')")
    timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')

    # Placeholder replacement via bash pattern substitution: unlike sed, it
    # treats "/", "&" and "\" in file paths as literal text.
    local html
    html=$(cat "$template")
    html=${html//'{{SUMMARY_JSON}}'/$summary_json}
    html=${html//'{{FINDINGS_JSON}}'/$findings_json}
    html=${html//'{{SCAN_INFO_JSON}}'/$scan_info_json}
    html=${html//'{{DURATION_MS}}'/$duration}
    html=${html//'{{TIMESTAMP}}'/$timestamp}

    if [[ "$html" == *'{{'* ]]; then
        log "WARN" "HTML template still contains unresolved placeholders"
    fi

    printf '%s\n' "$html" > "$output_file"

    if [[ ! -s "$output_file" ]]; then
        log "ERROR" "HTML report was not written"
        return 1
    fi

    echo -e "${CYAN}HTML dashboard saved to:${NC} $output_file"
    return 0
}

# ============================================================================
# JUNIT OUTPUT (for Jenkins)
# ============================================================================
output_junit() {
    local results="$1"
    local duration="${2:-0}"
    mkdir -p "$OUTPUT_DIR"
    local slug_part="${SCAN_TARGET_SLUG:+${SCAN_TARGET_SLUG}-}"
    local output_file="${OUTPUT_DIR}/webshell-scan-${slug_part}$(date +%Y%m%d-%H%M%S).xml"

    local scan_path
    scan_path=$(xml_escape "${PROJECT_ROOT:-}")
    local suite_seconds
    suite_seconds=$(awk -v d="$duration" 'BEGIN { printf "%.3f", d / 1000 }')

    local testcases=""
    local test_count=0
    local failure_count=0

    while IFS=$'\x1f' read -r file score severity yara; do
        [[ -z "$file" ]] && continue
        local safe_file safe_class
        safe_file=$(xml_escape "$file")
        safe_class="scan_$(basename "$file" | sed 's/[^a-zA-Z0-9]/_/g')"

        testcases+="    <testcase classname=\"WebshellScanner\" name=\"${safe_class}\" time=\"0\">"
        if [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]]; then
            testcases+="<failure message=\"${severity} finding (score ${score})\">$(xml_escape "$yara")</failure>"
            failure_count=$((failure_count + 1))
        elif [[ "$severity" == "MEDIUM" || "$severity" == "LOW" ]]; then
            testcases+="<skipped message=\"${severity} finding (score ${score})\"/>"
        fi
        testcases+="</testcase>"$'\n'
        test_count=$((test_count + 1))
    done < <(echo "$results" | jq -r '.findings[]? | [.file, (.score // 0), (.severity // "CLEAN"), ((.yara_matches // []) | join(", "))] | join("\u001f")')

    local clean_count
    clean_count=$(echo "$results" | jq -r '.summary.clean // 0')
    local i
    for ((i = 1; i <= clean_count; i++)); do
        testcases+="    <testcase classname=\"WebshellScanner\" name=\"clean_file_${i}\" time=\"0\"/>"$'\n'
        test_count=$((test_count + 1))
    done

    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        printf '<testsuite name="Webshell Scan" tests="%d" failures="%d" errors="0" time="%s" timestamp="%s">\n' \
            "$test_count" "$failure_count" "$suite_seconds" "$(date -u +%Y-%m-%dT%H:%M:%S)"
        echo '    <properties>'
        echo '        <property name="scanner_version" value="2.0"/>'
        printf '        <property name="scan_path" value="%s"/>\n' "$scan_path"
        echo '    </properties>'
        printf '%s' "$testcases"
        echo '</testsuite>'
    } > "$output_file"

    echo -e "${CYAN}JUnit XML saved to:${NC} $output_file"
    return 0
}

# ============================================================================
# MAIN OUTPUT DISPATCHER
# ============================================================================
output_results() {
    local results="$1"
    local duration="${2:-0}"

    # Compute summary
    local findings
    findings=$(echo "$results" | jq -c '.findings // []')
    local summary
    summary=$(echo "$findings" | jq '
        map(.severity) |
        {critical: map(select(. == "CRITICAL")) | length,
         high: map(select(. == "HIGH")) | length,
         medium: map(select(. == "MEDIUM")) | length,
         low: map(select(. == "LOW")) | length,
         info: map(select(. == "INFO")) | length,
         clean: 0}
    ')

    local total_files
    total_files=$(echo "$results" | jq -r '.scan_info.total_files // 0')
    local finding_count
    finding_count=$(echo "$summary" | jq -r '(.critical + .high + .medium + .low + .info)')
    local clean_files=$((total_files - finding_count))
    [[ $clean_files -lt 0 ]] && clean_files=0
    summary=$(echo "$summary" | jq --argjson c "$clean_files" '.clean = $c')

    results=$(echo "$results" | jq --argjson s "$summary" '.summary = $s')

    local format
    for format in "${OUTPUT_FORMATS[@]}"; do
        case "$format" in
            console) output_console "$results" "$duration" || log "ERROR" "console output failed" ;;
            json)    output_json "$results" "$duration"    || log "ERROR" "JSON output failed" ;;
            sarif)   output_sarif "$results" "$duration"   || log "ERROR" "SARIF output failed" ;;
            html)    output_html "$results" "$duration"    || log "ERROR" "HTML output failed" ;;
            junit)   output_junit "$results" "$duration"   || log "ERROR" "JUnit output failed" ;;
            "")      ;;
            *)       log "WARN" "Unknown output format: $format" ;;
        esac
    done

    return 0
}

# ============================================================================
# EXIT CODE DETERMINATION
# ============================================================================
compute_exit_code() {
    local results="$1"
    local fail_on
    fail_on=$(printf '%s' "${FAIL_ON:-HIGH}" | tr '[:lower:]' '[:upper:]')
    local fail_value
    fail_value=$(severity_value "$fail_on")
    [[ "$fail_value" -eq 0 ]] && fail_value=4

    local max_severity=0
    local severity val
    while IFS= read -r severity; do
        [[ -z "$severity" ]] && continue
        val=$(severity_value "$severity")
        [[ $val -gt $max_severity ]] && max_severity=$val
    done < <(echo "$results" | jq -r '.findings[]? | .severity // "CLEAN"')

    if [[ $max_severity -ge $fail_value ]]; then
        case $max_severity in
            5) echo 3; return 0 ;;  # CRITICAL
            4) echo 2; return 0 ;;  # HIGH
            3) echo 1; return 0 ;;  # MEDIUM
            2) echo 1; return 0 ;;  # LOW
            *) echo 0; return 0 ;;
        esac
    fi

    echo 0
}
