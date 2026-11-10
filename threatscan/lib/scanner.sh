#!/usr/bin/env bash
# File discovery and filtering for Advanced Webshell Scanner

# ============================================================================
# FILE DISCOVERY
# ============================================================================
find_scan_files() {
    local scan_dir="$1"

    # Git-aware mode: take the file list from git instead of matching find
    # -regex (GNU-only) against it. Works the same on BSD and GNU userland.
    if [[ "$GIT_CHANGED_ONLY" == "true" ]] || [[ -n "$GIT_SINCE_COMMIT" ]] || [[ -n "$GIT_DIFF" ]]; then
        local max_bytes
        max_bytes=$(parse_size "$MAX_FILE_SIZE")
        local rel full size
        while IFS= read -r rel; do
            [[ -z "$rel" ]] && continue
            full="${scan_dir}/${rel}"
            [[ -f "$full" ]] || continue
            size=$(get_file_size "$full")
            if [[ "$size" =~ ^[0-9]+$ ]] && [[ $size -gt $max_bytes ]]; then
                continue
            fi
            printf '%s\n' "$full"
        done < <(get_git_changed_files)
        return 0
    fi

    local find_cmd=("find" "$scan_dir" "-type" "f")
    
    # Follow symlinks?
    [[ "$FOLLOW_SYMLINKS" == "true" ]] && find_cmd+=("-L")
    
    # Max file size
    local max_bytes
    max_bytes=$(parse_size "$MAX_FILE_SIZE")
    find_cmd+=("-size" "-${max_bytes}c")
    
    # Exclude whitelisted paths
    for path in "${WHITELIST_PATHS[@]:-}"; do
        find_cmd+=("-not" "-path" "*/$path/*")
        find_cmd+=("-not" "-path" "$path/*")
    done
    
    # Default exclusions
    find_cmd+=("-not" "-path" "*/.git/*")
    find_cmd+=("-not" "-path" "*/.svn/*")
    find_cmd+=("-not" "-path" "*/node_modules/*")
    find_cmd+=("-not" "-path" "*/vendor/*")
    find_cmd+=("-not" "-path" "*/.idea/*")
    find_cmd+=("-not" "-path" "*/.vscode/*")
    find_cmd+=("-not" "-path" "*/__pycache__/*")
    find_cmd+=("-not" "-path" "*/.next/*")
    find_cmd+=("-not" "-path" "*/dist/*")
    find_cmd+=("-not" "-path" "*/build/*")
    find_cmd+=("-not" "-path" "*/.cache/*")
    find_cmd+=("-not" "-path" "*/coverage/*")
    
    # Execute find
    "${find_cmd[@]}" 2>/dev/null | sort -u
}

parse_size() {
    local size="$1"
    local num="${size%[KMG]B}"
    local unit="${size#$num}"
    # Convert to uppercase manually for bash 3.x compatibility
    case "$unit" in
        [kK][bB]) echo $((num * 1024)) ;;
        [mM][bB]) echo $((num * 1024 * 1024)) ;;
        [gG][bB]) echo $((num * 1024 * 1024 * 1024)) ;;
        *) echo "$size" ;;
    esac
}

# ============================================================================
# FILE FILTERING
# ============================================================================
should_scan_file() {
    local file="$1"
    
    # Whitelist check
    is_whitelisted "$file" && return 1
    
    local filename="${file##*/}"
    local filename_lower
    filename_lower=$(echo "$filename" | tr '[:upper:]' '[:lower:]')
    
    # Critical web configuration files often abused for backdoors/prepends
    case "$filename_lower" in
        .htaccess|.user.ini)
            return 0
            ;;
    esac

    # Polyglot or double-extension web execution tricks (e.g. avatar.php.jpg, shell.phtml.png)
    case "$filename_lower" in
        *.php.*|*.phtml.*|*.phar.*|*.shtml.*)
            return 0
            ;;
    esac

    # Extension check (web-accessible extensions)
    local ext="${file##*.}"
    local ext_lower
    ext_lower=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    # PHP and web extensions
    case "$ext_lower" in
        php|phtml|php3|php4|php5|php7|php8|phps|php-s|phar|pht|pgif|shtml|inc|module|theme|tpl|html|htm|js|css|json|xml|yaml|yml|txt|md|sql)
            is_text_file "$file" || return 1
            return 0
            ;;
    esac
    
    # Files without extension: check if text
    if [[ "$ext" == "$file" ]]; then
        is_text_file "$file" && return 0
    fi

    # Image / media files: check for polyglot webshell (embedded PHP tags)
    case "$ext_lower" in
        jpg|jpeg|png|gif|bmp|webp|ico|svg|pdf)
            if head -c 8192 "$file" 2>/dev/null | grep -q -E '<\?(php|=)'; then
                return 0
            fi
            ;;
    esac
    
    return 1
}

# ============================================================================
# INCREMENTAL SCAN SUPPORT
# ============================================================================
get_file_cache_key() {
    local file="$1"
    local hash
    hash=$(get_file_hash "$file")
    local mtime
    mtime=$(stat -c%Y "$file" 2>/dev/null || stat -f%m "$file" 2>/dev/null || echo 0)
    echo "${hash}:${mtime}"
}

check_cache() {
    local cache_key="$1"
    [[ -z "$CACHE_DIR" ]] && return 1
    [[ ! -f "${CACHE_DIR}/${cache_key}.json" ]] && return 1
    cat "${CACHE_DIR}/${cache_key}.json"
    return 0
}

write_cache() {
    local cache_key="$1"
    local result="$2"
    [[ -z "$CACHE_DIR" ]] && return
    echo "$result" > "${CACHE_DIR}/${cache_key}.json"
}

# Git-aware file discovery lives in lib/git.sh (get_git_changed_files).
