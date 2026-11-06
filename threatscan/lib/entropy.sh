#!/usr/bin/env bash
# Entropy analysis for Advanced Webshell Scanner
# Pure awk implementation: no bc, no per-window subprocess.

# Largest prefix of a file analysed for entropy. Webshell payloads are small;
# capping keeps a 10MB file from turning into millions of awk substr() calls.
ENTROPY_MAX_SAMPLE="${ENTROPY_MAX_SAMPLE:-262144}"

# ============================================================================
# SHANNON ENTROPY CALCULATION (string on stdin)
# ============================================================================
calculate_entropy() {
    local data="$1"
    printf '%s' "$data" | awk '
        { for (i = 1; i <= length($0); i++) { f[substr($0, i, 1)]++; t++ } }
        END {
            if (t == 0) { printf "0.0000"; exit }
            for (c in f) { p = f[c] / t; e -= p * log(p) / log(2) }
            printf "%.4f", e
        }'
}

calculate_entropy_awk() {
    calculate_entropy "$1"
}

# ============================================================================
# ENTROPY SCANNING
# ============================================================================
# Returns: overall|max_window|max_base64|[sections_json]
scan_entropy() {
    local file="$1"
    local min_len="${ENTROPY_MIN_LENGTH:-100}"
    local threshold="${ENTROPY_THRESHOLD:-7.5}"
    local maxbytes="${ENTROPY_MAX_SAMPLE:-262144}"

    if [[ ! -s "$file" ]]; then
        echo "0.0000|0.0000|0.0000|[]"
        return 0
    fi

    awk -v minlen="$min_len" -v thr="$threshold" -v maxbytes="$maxbytes" '
    function entropy(s,   i, n, c, f, p, e) {
        n = length(s)
        if (n == 0) return 0
        split("", f)
        for (i = 1; i <= n; i++) { c = substr(s, i, 1); f[c]++ }
        e = 0
        for (c in f) { p = f[c] / n; e -= p * log(p) / log(2) }
        return e
    }
    {
        buf = buf $0 "\n"
        if (length(buf) >= maxbytes) { buf = substr(buf, 1, maxbytes); done = 1 }
        if (done) exit
    }
    END {
        total = length(buf)
        if (total < minlen) { print "0.0000|0.0000|0.0000|[]"; exit }

        overall = entropy(buf)

        win = 256
        maxe = 0
        sections = ""
        count = 0
        for (start = 1; start + win - 1 <= total; start += win) {
            e = entropy(substr(buf, start, win))
            if (e > maxe) maxe = e
            if (e > thr) {
                count++
                if (count <= 50)
                    sections = sections (sections == "" ? "" : ",") \
                        sprintf("{\"offset\":%d,\"entropy\":%.4f,\"length\":%d}", start - 1, e, win)
            }
        }

        # Longest base64-like run (webshell payloads are usually one big blob)
        b64max = 0
        run = 0
        runstart = 1
        for (i = 1; i <= total; i++) {
            c = substr(buf, i, 1)
            if (c ~ /[A-Za-z0-9+\/=]/) {
                if (run == 0) runstart = i
                run++
            } else {
                if (run >= 100) {
                    e = entropy(substr(buf, runstart, run))
                    if (e > b64max) b64max = e
                }
                run = 0
            }
        }
        if (run >= 100) {
            e = entropy(substr(buf, runstart, run))
            if (e > b64max) b64max = e
        }

        printf "%.4f|%.4f|%.4f|[%s]\n", overall, maxe, b64max, sections
    }' "$file"
}

# ============================================================================
# ENTROPY CLASSIFICATION
# ============================================================================
classify_entropy() {
    local entropy="$1"
    if float_ge "$entropy" 7.5; then echo "CRITICAL"
    elif float_ge "$entropy" 7.0; then echo "HIGH"
    elif float_ge "$entropy" 6.0; then echo "MEDIUM"
    elif float_ge "$entropy" 5.0; then echo "LOW"
    else echo "CLEAN"
    fi
}

# ============================================================================
# FILE ENTROPY (for binary detection)
# ============================================================================
calculate_file_entropy() {
    local file="$1"
    [[ -r "$file" ]] || { echo "0"; return 0; }
    head -c 10240 "$file" 2>/dev/null | awk '
        { for (i = 1; i <= length($0); i++) { f[substr($0, i, 1)]++; t++ } }
        END {
            if (t == 0) { printf "0"; exit }
            for (c in f) { p = f[c] / t; e -= p * log(p) / log(2) }
            printf "%.4f", e
        }'
}
