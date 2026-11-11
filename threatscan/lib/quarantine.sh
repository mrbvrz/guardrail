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
            # shortcut: zip only accepts the password as an argument, so it is
            # visible in the process list for the lifetime of the command.
            # Upgrade to 7z/openssl if that exposure matters on the host.
            log "WARN" "Quarantine ZIP password is passed via argv (visible in ps)"
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
    local quarantine_archive="$1"
    [[ ! -f "$quarantine_archive" ]] && { echo "Quarantine file not found: $quarantine_archive" >&2; return 1; }
    
    local meta_file="${quarantine_archive}.meta.json"
    [[ ! -f "$meta_file" ]] && { echo "Metadata not found: $meta_file" >&2; return 1; }
    
    local original_path expected_hash
    original_path=$(jq -r '.original_path' "$meta_file" 2>/dev/null)
    expected_hash=$(jq -r '.hash // empty' "$meta_file" 2>/dev/null)
    
    [[ -z "$original_path" || "$original_path" == "null" ]] && { echo "Invalid metadata" >&2; return 1; }
    # Refuse absolute or traversal paths from a metadata file that may have
    # been edited: restore must stay inside the scan root.
    case "$original_path" in
        /*|..|../*|*/../*) echo "Unsafe original_path in metadata: $original_path" >&2; return 1 ;;
    esac
    
    local restore_path="${PROJECT_ROOT}/${original_path}"
    local staging
    staging=$(mktemp -d) || return 1

    local source_file=""
    if [[ "$quarantine_archive" == *.zip ]]; then
        if ! command -v unzip >/dev/null 2>&1; then
            echo "unzip not available for password-protected restore" >&2
            rm -rf "$staging"; return 1
        fi
        # -P with an empty password is rejected by unzip; archives created
        # without a password restore via the copy path below.
        if ! unzip -q -P "${QUARANTINE_PASSWORD}" -o "$quarantine_archive" -d "$staging" 2>/dev/null; then
            echo "Failed to extract quarantine archive (wrong password?)" >&2
            rm -rf "$staging"; return 1
        fi
        source_file=$(find "$staging" -type f -print 2>/dev/null | head -1)
    else
        cp "$quarantine_archive" "${staging}/restored" && source_file="${staging}/restored"
    fi

    if [[ -z "$source_file" ]]; then
        echo "Quarantine archive contained no file" >&2
        rm -rf "$staging"; return 1
    fi

    if [[ -n "$expected_hash" ]]; then
        local actual_hash
        actual_hash=$(get_file_hash "$source_file")
        if [[ "$actual_hash" != "$expected_hash" ]]; then
            echo "Hash mismatch (expected $expected_hash, got $actual_hash); refusing to restore" >&2
            rm -rf "$staging"; return 1
        fi
    fi

    mkdir -p "$(dirname "$restore_path")"
    mv "$source_file" "$restore_path"
    rm -rf "$staging"
    
    log "INFO" "Restored: $original_path from quarantine"
    echo "Restored to: $restore_path"
}

should_quarantine() {
    local severity="$1"
    local threshold="$QUARANTINE_THRESHOLD"
    
    local sev_val=$(severity_value "$severity")
    local thr_val=$(severity_value "$threshold")
    
    [[ $sev_val -ge $thr_val ]]
}