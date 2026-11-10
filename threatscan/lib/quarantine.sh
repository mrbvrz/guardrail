#!/usr/bin/env bash
# Quarantine management for Advanced Webshell Scanner

# ============================================================================
# QUARANTINE OPERATIONS
# ============================================================================
quarantine_file() {
    local file="$1"
    local severity="$2"
    local reason="$3"
    local scan_id="$4"
    
    [[ -z "$QUARANTINE_DIR" ]] && return 0
    
    local rel_file="${file#$PROJECT_ROOT/}"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local quarantine_name="${rel_file//\//_}.${timestamp}.quarantined"
    local quarantine_path="${QUARANTINE_DIR}/${quarantine_name}"
    
    # Calculate hash and size before moving/zipping the file
    local file_hash file_size iso_date
    file_hash=$(get_file_hash "$file")
    file_size=$(get_file_size "$file")
    iso_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")

    # Create quarantine directory structure
    mkdir -p "$(dirname "$quarantine_path")"
    
    if [[ -n "$QUARANTINE_PASSWORD" ]]; then
        # ZIP with password
        if command -v zip >/dev/null 2>&1; then
            zip -q -P "$QUARANTINE_PASSWORD" -j "${quarantine_path}.zip" "$file" 2>/dev/null
            rm -f "$file"
            quarantine_path="${quarantine_path}.zip"
        else
            # Fallback: move without zip
            mv "$file" "$quarantine_path"
        fi
    else
        # Move directly
        mv "$file" "$quarantine_path"
    fi
    
    # Write metadata
    local meta_file="${quarantine_path}.meta.json"
    cat > "$meta_file" << METAEOF
{
    "original_path": "$(json_escape "$rel_file")",
    "quarantine_path": "$(json_escape "$quarantine_name")",
    "severity": "$severity",
    "reason": "$(json_escape "$reason")",
    "scan_id": $scan_id,
    "timestamp": "$iso_date",
    "hash": "$file_hash",
    "size": $file_size,
    "password_protected": $([ -n "$QUARANTINE_PASSWORD" ] && echo true || echo false)
}
METAEOF
    
    log "INFO" "Quarantined: $rel_file -> $quarantine_name ($severity)"
    echo "$quarantine_path"
}

restore_from_quarantine() {
    local quarantine_file="$1"
    [[ ! -f "$quarantine_file" ]] && { echo "Quarantine file not found: $quarantine_file" >&2; return 1; }
    
    local meta_file="${quarantine_file}.meta.json"
    [[ ! -f "$meta_file" ]] && { echo "Metadata not found: $meta_file" >&2; return 1; }
    
    local original_path
    original_path=$(jq -r '.original_path' "$meta_file" 2>/dev/null)
    local password_protected
    password_protected=$(jq -r '.password_protected' "$meta_file" 2>/dev/null)
    
    [[ -z "$original_path" || "$original_path" == "null" ]] && { echo "Invalid metadata" >&2; return 1; }
    
    local restore_path="${PROJECT_ROOT}/${original_path}"
    mkdir -p "$(dirname "$restore_path")"
    
    if [[ "$password_protected" == "true" && -n "$QUARANTINE_PASSWORD" ]]; then
        if command -v unzip >/dev/null 2>&1; then
            unzip -q -P "$QUARANTINE_PASSWORD" -o "$quarantine_file" -d "$(dirname "$restore_path")" 2>/dev/null
            local extracted=$(basename "$quarantine_file" .quarantined.zip)
            mv "$(dirname "$restore_path")/$extracted" "$restore_path" 2>/dev/null || true
        else
            echo "unzip not available for password-protected restore" >&2
            return 1
        fi
    else
        cp "$quarantine_file" "$restore_path"
    fi
    
    log "INFO" "Restored: $original_path from quarantine"
    echo "Restored to: $restore_path"
}

list_quarantine() {
    [[ -z "$QUARANTINE_DIR" ]] && echo "[]" && return
    [[ ! -d "$QUARANTINE_DIR" ]] && echo "[]" && return
    
    local results=()
    while IFS= read -r -d '' meta_file; do
        [[ -f "$meta_file" ]] || continue
        local data
        data=$(cat "$meta_file")
        results+=("$data")
    done < <(find "$QUARANTINE_DIR" -name "*.meta.json" -print0 2>/dev/null)
    
    local json="["
    local first=true
    for r in "${results[@]}"; do
        [[ "$first" == "true" ]] && first=false || json+=","
        json+="$r"
    done
    json+="]"
    echo "$json"
}

should_quarantine() {
    local severity="$1"
    local threshold="$QUARANTINE_THRESHOLD"
    
    local sev_val=$(severity_value "$severity")
    local thr_val=$(severity_value "$threshold")
    
    [[ $sev_val -ge $thr_val ]]
}