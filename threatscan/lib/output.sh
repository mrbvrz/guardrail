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
    local output_file="${OUTPUT_DIR}/webshell-scan-$(date +%Y%m%d-%H%M%S).json"

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
    local output_file="${OUTPUT_DIR}/webshell-scan-$(date +%Y%m%d-%H%M%S).sarif"

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
    local output_file="${OUTPUT_DIR}/webshell-scan-$(date +%Y%m%d-%H%M%S).html"

    local template="${TEMPLATES_DIR}/dashboard.html"
    if [[ ! -s "$template" ]]; then
        mkdir -p "$TEMPLATES_DIR" 2>/dev/null || true
        generate_html_template "$template" >/dev/null 2>&1 || true
    fi
    # Read-only install: fall back to a temporary template
    if [[ ! -s "$template" ]]; then
        template=$(mktemp)
        generate_html_template "$template" >/dev/null 2>&1 || true
    fi
    if [[ ! -s "$template" ]]; then
        log "ERROR" "HTML template unavailable at ${TEMPLATES_DIR}/dashboard.html"
        echo -e "${RED}HTML report failed: template unavailable${NC}" >&2
        return 1
    fi

    local summary_json findings_json scan_info_json timestamp
    summary_json=$(echo "$results" | jq -c '.summary // {}')
    findings_json=$(echo "$results" | jq -c '.findings // []')
    scan_info_json=$(echo "$results" | jq -c '.scan_info // {}')
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

generate_html_template() {
    local output_file="$1"
    mkdir -p "$(dirname "$output_file")" 2>/dev/null || true
    cat > "$output_file" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Webshell Scan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #1a1a1a; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .header h1 { font-size: 1.5rem; }
        .header .meta { color: #666; margin-top: 8px; font-size: 0.875rem; line-height: 1.6; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .card.critical { border-left: 4px solid #dc2626; }
        .card.high { border-left: 4px solid #ef4444; }
        .card.medium { border-left: 4px solid #f59e0b; }
        .card.low { border-left: 4px solid #eab308; }
        .card.clean { border-left: 4px solid #22c55e; }
        .card .value { font-size: 2.5rem; font-weight: 700; line-height: 1; }
        .card .label { color: #666; margin-top: 4px; font-size: 0.875rem; }
        .chart-container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; min-height: 200px; }
        .bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; font-size: 0.875rem; }
        .bar-label { width: 80px; color: #374151; }
        .bar-track { flex: 1; background: #f3f4f6; border-radius: 4px; height: 18px; overflow: hidden; }
        .bar-fill { height: 100%; border-radius: 4px; }
        .bar-value { width: 48px; text-align: right; font-family: monospace; color: #374151; }
        .findings-table { background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #eee; font-size: 0.875rem; }
        th { background: #f9fafb; font-weight: 600; color: #374151; white-space: nowrap; }
        tbody tr:hover { background: #f9fafb; }
        .severity { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .severity-critical { background: #fef2f2; color: #dc2626; }
        .severity-high { background: #fef2f2; color: #ef4444; }
        .severity-medium { background: #fffbeb; color: #f59e0b; }
        .severity-low { background: #fffbeb; color: #b45309; }
        .severity-info { background: #eff6ff; color: #3b82f6; }
        .severity-clean { background: #f0fdf4; color: #16a34a; }
        .score { font-family: monospace; font-weight: 600; }
        .details { max-width: 320px; color: #666; }
        .file-link { color: #3b82f6; text-decoration: none; word-break: break-all; }
        .file-link:hover { text-decoration: underline; }
        .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal.active { display: flex; align-items: center; justify-content: center; }
        .modal-content { background: #fff; width: 90%; max-width: 800px; max-height: 90vh; border-radius: 8px; overflow: hidden; }
        .modal-header { padding: 16px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .modal-header h3 { font-size: 1rem; word-break: break-all; }
        .modal-body { padding: 16px; overflow: auto; max-height: 70vh; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: 600; margin: 0 4px 4px 0; background: #dbeafe; color: #1e40af; }
        .tabs { display: flex; flex-wrap: wrap; border-bottom: 1px solid #eee; margin-bottom: 16px; }
        .tab { padding: 8px 16px; cursor: pointer; border-bottom: 2px solid transparent; font-size: 0.875rem; }
        .tab.active { border-bottom-color: #3b82f6; color: #3b82f6; font-weight: 600; }
        .tab-panel { display: none; font-size: 0.875rem; line-height: 1.7; }
        .tab-panel.active { display: block; }
        .empty { padding: 32px; text-align: center; color: #6b7280; }
        pre { background: #f9fafb; padding: 12px; border-radius: 4px; overflow: auto; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Webshell Scan Report</h1>
            <div class="meta" id="reportMeta"></div>
        </div>

        <div class="summary" id="summary"></div>

        <div class="chart-container">
            <canvas id="severityChart" height="180"></canvas>
            <div id="chartFallback"></div>
        </div>

        <div class="findings-table">
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Score</th>
                        <th>Severity</th>
                        <th>YARA</th>
                        <th>Entropy</th>
                        <th>Signals</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody id="findingsBody"></tbody>
            </table>
            <div class="empty" id="emptyState" style="display:none;">No findings.</div>
        </div>
    </div>

    <div class="modal" id="detailModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Finding Details</h3>
                <button onclick="closeModal()" style="background:none;border:none;font-size:1.5rem;cursor:pointer;line-height:1;">&times;</button>
            </div>
            <div class="modal-body">
                <div class="tabs">
                    <div class="tab active" onclick="showTab(event, 'overview')">Overview</div>
                    <div class="tab" onclick="showTab(event, 'yara')">YARA</div>
                    <div class="tab" onclick="showTab(event, 'entropy')">Entropy</div>
                    <div class="tab" onclick="showTab(event, 'heuristics')">Heuristics</div>
                    <div class="tab" onclick="showTab(event, 'code')">Code</div>
                </div>
                <div id="overview" class="tab-panel active"></div>
                <div id="yara" class="tab-panel"></div>
                <div id="entropy" class="tab-panel"></div>
                <div id="heuristics" class="tab-panel"></div>
                <div id="code" class="tab-panel"></div>
            </div>
        </div>
    </div>

    <script>
        // Injected at report build time
        const SUMMARY = {{SUMMARY_JSON}};
        const FINDINGS = {{FINDINGS_JSON}};
        const SCAN_INFO = {{SCAN_INFO_JSON}};
        const DURATION_MS = {{DURATION_MS}};
        const GENERATED_AT = "{{TIMESTAMP}}";

        const SEVERITY_COLORS = {
            critical: '#dc2626', high: '#ef4444', medium: '#f59e0b',
            low: '#eab308', clean: '#22c55e'
        };

        function el(id) { return document.getElementById(id); }

        function renderMeta() {
            const info = SCAN_INFO || {};
            const duration = typeof DURATION_MS === 'number'
                ? DURATION_MS + ' ms' : 'n/a';
            el('reportMeta').innerHTML =
                'Scan ID: ' + (info.scan_id || 'n/a') + '<br>' +
                'Target: ' + (info.scanned_path || 'n/a') + '<br>' +
                'Files scanned: ' + (info.total_files || 0) +
                ' &middot; Duration: ' + duration +
                ' &middot; Generated: ' + GENERATED_AT;
        }

        function renderSummary() {
            const severities = [
                ['critical', 'Critical'], ['high', 'High'],
                ['medium', 'Medium'], ['low', 'Low'], ['clean', 'Clean']
            ];
            el('summary').innerHTML = severities.map(([key, label]) =>
                '<div class="card ' + key + '">' +
                '<div class="value">' + (SUMMARY[key] || 0) + '</div>' +
                '<div class="label">' + label + '</div></div>').join('');
        }

        function renderChart() {
            const data = [
                SUMMARY.critical || 0, SUMMARY.high || 0, SUMMARY.medium || 0,
                SUMMARY.low || 0, SUMMARY.clean || 0
            ];
            const labels = ['Critical', 'High', 'Medium', 'Low', 'Clean'];
            const colors = labels.map(l => SEVERITY_COLORS[l.toLowerCase()]);

            // Chart.js comes from a CDN; air-gapped servers still get bars.
            if (typeof Chart !== 'undefined') {
                try {
                    new Chart(el('severityChart').getContext('2d'), {
                        type: 'doughnut',
                        data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderWidth: 0 }] },
                        options: { responsive: true, maintainAspectRatio: false,
                                   plugins: { legend: { position: 'bottom' } } }
                    });
                    return;
                } catch (e) { /* fall through to bars */ }
            }

            el('severityChart').style.display = 'none';
            const max = Math.max.apply(null, data.concat([1]));
            el('chartFallback').innerHTML = labels.map((label, i) => {
                const width = Math.round((data[i] / max) * 100);
                return '<div class="bar-row"><span class="bar-label">' + label + '</span>' +
                    '<span class="bar-track"><span class="bar-fill" style="width:' + width +
                    '%;background:' + colors[i] + '"></span></span>' +
                    '<span class="bar-value">' + data[i] + '</span></div>';
            }).join('');
        }

        function signalBadges(heuristics) {
            return Object.keys(heuristics || {})
                .filter(k => heuristics[k] && heuristics[k].count > 0)
                .map(k => '<span class="badge">' + k + ': ' + heuristics[k].count + '</span>')
                .join('');
        }

        function renderFindings() {
            const tbody = el('findingsBody');
            if (!FINDINGS.length) {
                tbody.innerHTML = '';
                el('emptyState').style.display = 'block';
                return;
            }
            tbody.innerHTML = FINDINGS.map((f, i) => {
                const sev = (f.severity || 'CLEAN').toLowerCase();
                const yara = (f.yara_matches || []).join(', ') || '-';
                const entropy = Number((f.entropy || {}).max || 0).toFixed(2);
                return '<tr onclick="showDetail(' + i + ')" style="cursor:pointer;">' +
                    '<td><a class="file-link" href="#" onclick="event.stopPropagation();showDetail(' + i + ')">' +
                    f.file + '</a></td>' +
                    '<td class="score">' + (f.score || 0) + '</td>' +
                    '<td><span class="severity severity-' + sev + '">' + (f.severity || 'CLEAN') + '</span></td>' +
                    '<td>' + yara + '</td>' +
                    '<td>' + entropy + '</td>' +
                    '<td>' + signalBadges(f.heuristics) + '</td>' +
                    '<td class="details">' + (f.heuristics ? 'score ' + (f.heuristic_score || 0) : '-') + '</td>' +
                    '</tr>';
            }).join('');
        }

        function renderHeuristicsTable(heuristics) {
            const keys = Object.keys(heuristics || {});
            if (!keys.length) return '<p>No heuristic signals.</p>';
            let rows = keys.map(k => {
                const d = heuristics[k] || {};
                return '<tr><td>' + k + '</td><td>' + (d.count || 0) + '</td><td>' +
                    (d.weight || 0) + '</td><td>' + ((d.count || 0) * (d.weight || 0)) +
                    '</td><td>' + ((d.details || []).join(', ') || '-') + '</td></tr>';
            }).join('');
            return '<table><tr><th>Signal</th><th>Count</th><th>Weight</th>' +
                '<th>Contribution</th><th>Details</th></tr>' + rows + '</table>';
        }

        function showDetail(index) {
            const f = FINDINGS[index];
            if (!f) return;
            el('modalTitle').textContent = f.file;
            const ent = f.entropy || {};

            el('overview').innerHTML =
                '<p><strong>Score:</strong> ' + (f.score || 0) + ' (' + (f.severity || 'CLEAN') + ')</p>' +
                '<p><strong>Path:</strong> ' + (f.file || '') + '</p>' +
                '<p><strong>Size:</strong> ' + (f.size || 0) + ' bytes</p>' +
                '<p><strong>SHA-256:</strong> <code>' + (f.hash || 'n/a') + '</code></p>' +
                '<p><strong>YARA:</strong> ' + ((f.yara_matches || []).join(', ') || 'none') + '</p>' +
                '<p><strong>Entropy:</strong> overall ' + Number(ent.overall || 0).toFixed(4) +
                ', max ' + Number(ent.max || 0).toFixed(4) + '</p>' +
                '<p><strong>Signatures:</strong> ' +
                ((f.signatures || []).map(s => s.name || s.function || s.type || '').join(', ') || 'none') + '</p>';

            el('yara').innerHTML = (f.yara_matches || []).length
                ? '<ul>' + f.yara_matches.map(m => '<li>' + m + '</li>').join('') + '</ul>'
                : '<p>No YARA matches.</p>';

            el('entropy').innerHTML =
                '<p><strong>Overall:</strong> ' + Number(ent.overall || 0).toFixed(4) + '</p>' +
                '<p><strong>Max window:</strong> ' + Number(ent.max || 0).toFixed(4) + '</p>' +
                '<p><strong>Max base64 run:</strong> ' + Number(ent.b64_max || 0).toFixed(4) + '</p>' +
                '<p><strong>High entropy sections:</strong> ' + (ent.sections || []).length + '</p>' +
                '<pre>' + JSON.stringify(ent.sections || [], null, 2) + '</pre>';

            el('heuristics').innerHTML = renderHeuristicsTable(f.heuristics);
            el('code').innerHTML = '<p>Code view is not embedded in the report. Open the file on the scanned host to inspect it.</p>';

            el('detailModal').classList.add('active');
        }

        function closeModal() {
            el('detailModal').classList.remove('active');
        }

        function showTab(evt, name) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            if (evt && evt.currentTarget) evt.currentTarget.classList.add('active');
            el(name).classList.add('active');
        }

        document.addEventListener('DOMContentLoaded', function () {
            // Each renderer is isolated: a failure in one must not blank the page.
            [renderMeta, renderSummary, renderFindings, renderChart].forEach(function (fn) {
                try { fn(); } catch (e) { console.error(fn.name, e); }
            });
        });

        el('detailModal').addEventListener('click', function (e) {
            if (e.target === e.currentTarget) closeModal();
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closeModal();
        });
    </script>
</body>
</html>
HTMLEOF
}

# ============================================================================
# JUNIT OUTPUT (for Jenkins)
# ============================================================================
output_junit() {
    local results="$1"
    local duration="${2:-0}"
    mkdir -p "$OUTPUT_DIR"
    local output_file="${OUTPUT_DIR}/webshell-scan-$(date +%Y%m%d-%H%M%S).xml"

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
determine_exit_code() {
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
            5) exit 3 ;;  # CRITICAL
            4) exit 2 ;;  # HIGH
            3) exit 1 ;;  # MEDIUM
            2) exit 1 ;;  # LOW
            *) exit 0 ;;
        esac
    fi

    exit 0
}
