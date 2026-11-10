#!/usr/bin/env bash
# Auto-discovery and interactive web target selection for ThreatScan

# ============================================================================
# DISCOVERY STATE
# ============================================================================
DISCOVERED_PATHS=()
DISCOVERED_SOURCES=()
DISCOVERED_TYPES=()
DISCOVERED_COUNTS=()

# ============================================================================
# DIRECTORY CLASSIFICATION HELPERS
# ============================================================================

# Directories that are never standalone web projects
is_ignored_web_subdir() {
    local name="$1"
    case "$name" in
        .*|node_modules|vendor|storage|logs|log|tmp|temp|cache|backup|backups|\
        cgi-bin|quarantine|reports|plesk-stat|webalizer|awstats|stats|error|\
        errors|icons|manual|xampp|dashboard|img|images|css|js|fonts|assets|\
        static|media|uploads|upload|files|downloads|includes|inc|lib|libs|\
        src|config|conf|database|db|migrations|resources|routes|bootstrap|\
        tests|test|spec|views|controllers|models|modules|plugins|themes|\
        templates|lang|languages|locale|locales|bin|scripts|docs|doc|\
        wp-admin|wp-content|wp-includes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Check if a directory is itself a single framework application root
is_single_framework_root() {
    local dir="$1"
    # Laravel
    [[ -f "$dir/artisan" && -f "$dir/composer.json" ]] && return 0
    # WordPress
    [[ -f "$dir/wp-config.php" || -f "$dir/wp-config-sample.php" || -d "$dir/wp-includes" ]] && return 0
    # CodeIgniter 4 / 3
    [[ -f "$dir/spark" && -f "$dir/composer.json" ]] && return 0
    [[ -d "$dir/system" && -d "$dir/application" && -f "$dir/index.php" ]] && return 0
    # Symfony
    [[ -f "$dir/bin/console" && -f "$dir/symfony.lock" ]] && return 0
    # Drupal
    [[ -f "$dir/core/lib/Drupal.php" || ( -d "$dir/sites/default" && -f "$dir/index.php" ) ]] && return 0
    # Joomla
    [[ -f "$dir/configuration.php" && -d "$dir/administrator" ]] && return 0
    return 1
}

# Check if a directory has its own web project entrypoint or markers
has_web_project_markers() {
    local dir="$1"
    is_single_framework_root "$dir" && return 0
    [[ -f "$dir/index.php" || -f "$dir/index.html" || -f "$dir/index.htm" ]] && return 0
    [[ -f "$dir/public/index.php" || -f "$dir/public/index.html" ]] && return 0
    [[ -f "$dir/composer.json" || -f "$dir/.htaccess" || -f "$dir/default.php" ]] && return 0

    # Check if there is at least one PHP file within depth 2
    local php_found
    php_found=$(find "$dir" -maxdepth 2 -type f \( -name "*.php" -o -name "*.phtml" \) 2>/dev/null | head -n 1)
    [[ -n "$php_found" ]] && return 0

    return 1
}

# Detect application / framework type for display
detect_app_type() {
    local dir="$1"
    if [[ -f "$dir/artisan" && -f "$dir/composer.json" ]]; then
        echo "Laravel"
    elif [[ -f "$dir/wp-config.php" || -f "$dir/wp-config-sample.php" || -d "$dir/wp-includes" ]]; then
        echo "WordPress"
    elif [[ -f "$dir/spark" ]] || [[ -d "$dir/system" && -d "$dir/application" ]] || [[ -d "$dir/app/Config" && -f "$dir/composer.json" ]]; then
        echo "CodeIgniter"
    elif [[ -f "$dir/bin/console" && -f "$dir/symfony.lock" ]]; then
        echo "Symfony"
    elif [[ -f "$dir/core/lib/Drupal.php" || -d "$dir/sites/default" ]]; then
        echo "Drupal"
    elif [[ -f "$dir/configuration.php" && -d "$dir/administrator" ]]; then
        echo "Joomla"
    elif [[ -f "$dir/composer.json" ]]; then
        echo "Composer PHP"
    elif [[ -n "$(find "$dir" -maxdepth 2 -type f \( -name "*.php" -o -name "*.phtml" \) 2>/dev/null | head -n 1)" ]]; then
        echo "Native PHP"
    elif [[ -f "$dir/index.html" || -f "$dir/index.htm" || -f "$dir/.htaccess" ]]; then
        echo "Static/Web"
    else
        echo "Web Folder"
    fi
}

# Fast approximate file count for display in selection menu
estimate_file_count() {
    local dir="$1"
    local count
    count=$(find "$dir" \
        \( -name ".git" -o -name "node_modules" -o -name "vendor" \) -prune -o \
        -type f -print 2>/dev/null | wc -l | tr -d '[:space:]')
    echo "${count:-0}"
}

# Add a candidate path to DISCOVERED_* arrays if not already present
register_discovered_target() {
    local raw_path="$1"
    local source_label="$2"

    [[ -z "$raw_path" || ! -d "$raw_path" ]] && return 1

    local norm_path
    norm_path=$(realpath "$raw_path" 2>/dev/null || (cd "$raw_path" 2>/dev/null && pwd) || echo "${raw_path%/}")
    [[ -z "$norm_path" || ! -d "$norm_path" ]] && return 1

    # Deduplicate
    local existing
    if [[ ${#DISCOVERED_PATHS[@]} -gt 0 ]]; then
        for existing in "${DISCOVERED_PATHS[@]}"; do
            if [[ "$existing" == "$norm_path" ]]; then
                return 0
            fi
        done
    fi

    local app_type file_count
    app_type=$(detect_app_type "$norm_path")
    file_count=$(estimate_file_count "$norm_path")

    DISCOVERED_PATHS+=("$norm_path")
    DISCOVERED_SOURCES+=("$source_label")
    DISCOVERED_TYPES+=("$app_type")
    DISCOVERED_COUNTS+=("$file_count")
    return 0
}

# ============================================================================
# SUB-PROJECT EXPANSION (e.g. /var/www/html -> web-a, web-b)
# ============================================================================

# Inspect a base directory (e.g. /var/www/html). If it contains sub-projects
# (like web-a, web-b), register each sub-project and return 0.
# Returns 1 if base_dir is a single project or has no sub-projects.
expand_web_subprojects() {
    local base_dir="$1"
    local source_label="${2:-subfolder}"

    [[ ! -d "$base_dir" ]] && return 1

    # If the base directory itself is a known framework root (Laravel, WP, etc.),
    # do not split its internal directories into separate projects.
    if is_single_framework_root "$base_dir"; then
        return 1
    fi

    # Check whether base_dir has a root entrypoint of its own
    local parent_has_entrypoint=false
    if [[ -f "$base_dir/index.php" || -f "$base_dir/index.html" || -f "$base_dir/index.htm" || -f "$base_dir/composer.json" ]]; then
        parent_has_entrypoint=true
    fi

    local subdirs=()
    local entry base_name
    for entry in "$base_dir"/*/; do
        [[ ! -d "$entry" ]] && continue
        entry="${entry%/}"
        base_name=$(basename "$entry")

        # Skip hidden or known non-project directories
        if is_ignored_web_subdir "$base_name"; then
            continue
        fi

        if [[ "$parent_has_entrypoint" == "false" ]]; then
            # Pure container directory (e.g., /var/www/html with web-a, web-b):
            # accept any non-ignored subdirectory that is non-empty or has web markers
            if has_web_project_markers "$entry" || [[ -n "$(find "$entry" -maxdepth 2 -mindepth 1 2>/dev/null | head -n 1)" ]]; then
                subdirs+=("$entry")
            fi
        else
            # Parent has an index file (e.g., default welcome page):
            # only treat subdirectories with explicit web project markers as separate projects
            if has_web_project_markers "$entry"; then
                subdirs+=("$entry")
            fi
        fi
    done

    if [[ ${#subdirs[@]} -eq 0 ]]; then
        return 1
    fi

    local sub
    for sub in "${subdirs[@]}"; do
        register_discovered_target "$sub" "$source_label"
    done
    return 0
}

# ============================================================================
# SYSTEM-WIDE WEB ROOT DISCOVERY
# ============================================================================

# Extract root paths from Nginx configuration files
discover_nginx_roots() {
    local conf_files=()
    local pattern f
    for pattern in \
        "/etc/nginx/sites-enabled/*" \
        "/etc/nginx/conf.d/*.conf" \
        "/etc/nginx/nginx.conf" \
        "/usr/local/etc/nginx/servers/*" \
        "/opt/homebrew/etc/nginx/servers/*"; do
        for f in $pattern; do
            [[ -f "$f" && -r "$f" ]] && conf_files+=("$f")
        done
    done

    [[ ${#conf_files[@]} -eq 0 ]] && return 0

    local path
    while IFS= read -r path; do
        [[ -z "$path" || ! -d "$path" ]] && continue
        if ! expand_web_subprojects "$path" "nginx vhost"; then
            register_discovered_target "$path" "nginx vhost"
        fi
    done < <(awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*root[[:space:]]+/ {
            sub(/^[[:space:]]*root[[:space:]]+/, "")
            sub(/[[:space:]]*;.*$/, "")
            gsub(/["\047]/, "")
            if ($0 != "" && $0 !~ /^\/usr\/share\/nginx\/html$/) print $0
        }
    ' "${conf_files[@]}" 2>/dev/null | sort -u)
}

# Extract DocumentRoot paths from Apache/HTTPD configuration files
discover_apache_roots() {
    local conf_files=()
    local pattern f
    for pattern in \
        "/etc/apache2/sites-enabled/*" \
        "/etc/apache2/conf-enabled/*" \
        "/etc/httpd/conf.d/*.conf" \
        "/etc/httpd/conf/httpd.conf" \
        "/etc/apache2/apache2.conf"; do
        for f in $pattern; do
            [[ -f "$f" && -r "$f" ]] && conf_files+=("$f")
        done
    done

    [[ ${#conf_files[@]} -eq 0 ]] && return 0

    local path
    while IFS= read -r path; do
        [[ -z "$path" || ! -d "$path" ]] && continue
        if ! expand_web_subprojects "$path" "apache vhost"; then
            register_discovered_target "$path" "apache vhost"
        fi
    done < <(awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*DocumentRoot[[:space:]]+/ {
            sub(/^[[:space:]]*DocumentRoot[[:space:]]+/, "")
            sub(/[[:space:]]*#.*$/, "")
            sub(/[[:space:]]+$/, "")
            gsub(/["\047]/, "")
            if ($0 != "") print $0
        }
    ' "${conf_files[@]}" 2>/dev/null | sort -u)
}

# Check standard Linux / macOS web root directories
discover_standard_roots() {
    local std_roots=(
        "/var/www/html"
        "/var/www"
        "/srv/www/htdocs"
        "/srv/www"
        "/opt/lampp/htdocs"
        "/usr/share/nginx/html"
    )

    local dir
    for dir in "${std_roots[@]}"; do
        [[ ! -d "$dir" ]] && continue
        # Avoid scanning /var/www directly as a single site if it only holds /var/www/html
        if [[ "$dir" == "/var/www" && -d "/var/www/html" ]]; then
            local extra_in_var_www=false
            local sub
            for sub in /var/www/*/; do
                [[ ! -d "$sub" ]] && continue
                sub="${sub%/}"
                [[ "$sub" == "/var/www/html" ]] && continue
                if ! is_ignored_web_subdir "$(basename "$sub")" && has_web_project_markers "$sub"; then
                    register_discovered_target "$sub" "subfolder (/var/www)"
                    extra_in_var_www=true
                fi
            done
            continue
        fi

        if ! expand_web_subprojects "$dir" "subfolder ($dir)"; then
            if has_web_project_markers "$dir"; then
                register_discovered_target "$dir" "standard webroot"
            fi
        fi
    done

    # Check user public_html / www directories
    local user_dir
    for user_dir in /home/*/public_html /home/*/www /Users/*/Sites; do
        [[ ! -d "$user_dir" ]] && continue
        if ! expand_web_subprojects "$user_dir" "user webroot"; then
            if has_web_project_markers "$user_dir"; then
                register_discovered_target "$user_dir" "user webroot"
            fi
        fi
    done
}

# Run full discovery (either scoped to a given parent directory or system-wide)
discover_web_targets() {
    local target_root="${1:-}"
    DISCOVERED_PATHS=()
    DISCOVERED_SOURCES=()
    DISCOVERED_TYPES=()
    DISCOVERED_COUNTS=()

    if [[ -n "$target_root" && -d "$target_root" ]]; then
        if ! expand_web_subprojects "$target_root" "subfolder ($target_root)"; then
            register_discovered_target "$target_root" "target path"
        fi
        return 0
    fi

    # System-wide discovery
    discover_nginx_roots
    discover_apache_roots
    discover_standard_roots
    return 0
}

# ============================================================================
# DISPLAY & INTERACTIVE MENU
# ============================================================================

# Print discovered targets table (used by --list-targets)
print_discovered_targets() {
    local count=${#DISCOVERED_PATHS[@]}
    if [[ $count -eq 0 ]]; then
        echo -e "${YELLOW}No web directories discovered.${NC}"
        return 1
    fi

    echo -e "${BOLD}Discovered Web Targets (${count}):${NC}"
    printf "  ${BOLD}%-4s %-44s %-15s %-12s %s${NC}\n" "NO" "PATH" "TYPE" "FILES" "SOURCE"
    printf "  %-4s %-44s %-15s %-12s %s\n" "---" "----" "----" "-----" "------"

    local i
    for ((i = 0; i < count; i++)); do
        printf "  ${CYAN}[%d]${NC}  %-44s %-15s %-12s %s\n" \
            "$((i + 1))" \
            "${DISCOVERED_PATHS[$i]}" \
            "${DISCOVERED_TYPES[$i]}" \
            "~${DISCOVERED_COUNTS[$i]}" \
            "${DISCOVERED_SOURCES[$i]}"
    done
    return 0
}

# Parse user selection like "1", "1,2", "1-3", "1 3" into 0-based indices
parse_selection_indices() {
    local input="$1"
    local max="$2"
    local selected=()
    local token start end idx existing already

    # Replace commas with spaces
    input="${input//,/ }"

    for token in $input; do
        if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            if [[ $start -lt 1 || $end -gt $max || $start -gt $end ]]; then
                return 1
            fi
            for ((idx = start; idx <= end; idx++)); do
                already=false
                if [[ ${#selected[@]} -gt 0 ]]; then
                    for existing in "${selected[@]}"; do
                        [[ "$existing" -eq $((idx - 1)) ]] && already=true
                    done
                fi
                [[ "$already" == "false" ]] && selected+=("$((idx - 1))")
            done
        elif [[ "$token" =~ ^[0-9]+$ ]]; then
            if [[ $token -lt 1 || $token -gt $max ]]; then
                return 1
            fi
            already=false
            if [[ ${#selected[@]} -gt 0 ]]; then
                for existing in "${selected[@]}"; do
                    [[ "$existing" -eq $((token - 1)) ]] && already=true
                done
            fi
            [[ "$already" == "false" ]] && selected+=("$((token - 1))")
        else
            return 1
        fi
    done

    [[ ${#selected[@]} -eq 0 ]] && return 1
    printf '%s\n' "${selected[@]}"
    return 0
}

# Interactive prompt to choose which web target(s) to scan
# Populates global SCAN_TARGETS array.
prompt_target_selection() {
    local parent_root="${1:-}"
    local count=${#DISCOVERED_PATHS[@]}

    SCAN_TARGETS=()

    if [[ $count -eq 0 ]]; then
        return 1
    fi

    # If --all-targets or --yes is set, select all discovered targets automatically
    if [[ "${ALL_TARGETS:-false}" == "true" || "${AUTO_YES:-false}" == "true" ]]; then
        SCAN_TARGETS=("${DISCOVERED_PATHS[@]}")
        return 0
    fi

    # Non-interactive terminal fallback (unless -i/--discover explicitly requested):
    # if parent_root was given, scan parent_root; otherwise scan all discovered targets.
    if [[ ! -t 0 && "${DISCOVER_MODE:-false}" != "true" ]]; then
        if [[ -n "$parent_root" && -d "$parent_root" ]]; then
            SCAN_TARGETS=("$parent_root")
        else
            SCAN_TARGETS=("${DISCOVERED_PATHS[@]}")
        fi
        return 0
    fi

    echo "" >&2
    if [[ -n "$parent_root" ]]; then
        echo -e "${CYAN}${BOLD}[*]${NC} Found ${BOLD}${count}${NC} web project(s) under ${BOLD}${parent_root}${NC}:" >&2
    else
        echo -e "${CYAN}${BOLD}[*]${NC} Auto-discovered ${BOLD}${count}${NC} web project(s) on system:" >&2
    fi
    echo "" >&2

    local i
    for ((i = 0; i < count; i++)); do
        printf "  ${CYAN}${BOLD}[%d]${NC} %-42s ${DIM}(%-12s • ~%s files • %s)${NC}\n" \
            "$((i + 1))" \
            "${DISCOVERED_PATHS[$i]}" \
            "${DISCOVERED_TYPES[$i]}" \
            "${DISCOVERED_COUNTS[$i]}" \
            "${DISCOVERED_SOURCES[$i]}" >&2
    done

    echo -e "  ${DIM}──────────────────────────────────────────────────────────────────────────────${NC}" >&2
    if [[ $count -gt 1 ]]; then
        echo -e "  ${GREEN}${BOLD}[A]${NC} Scan ALL projects sequentially (1-${count})" >&2
    fi
    if [[ -n "$parent_root" && -d "$parent_root" && $count -gt 1 ]]; then
        echo -e "  ${BLUE}${BOLD}[R]${NC} Scan parent root directly as a single scan (${parent_root})" >&2
    fi
    echo -e "  ${RED}${BOLD}[Q]${NC} Quit" >&2
    echo "" >&2

    # If only 1 target was found during system discovery, offer simple Y/n confirmation
    if [[ $count -eq 1 ]]; then
        local confirm
        printf "${BOLD}Scan %s? [Y/n]: ${NC}" "${DISCOVERED_PATHS[0]}" >&2
        read -r confirm
        case "$confirm" in
            [nN]|[nN][oO]|[qQ])
                echo -e "${YELLOW}Scan cancelled.${NC}" >&2
                exit 0
                ;;
            *)
                SCAN_TARGETS=("${DISCOVERED_PATHS[0]}")
                return 0
                ;;
        esac
    fi

    # Multiple targets: loop until valid selection
    local choice
    while true; do
        if [[ -n "$parent_root" ]]; then
            printf "${BOLD}Select target to scan (e.g. 1, 1,2, 1-%d, A, R, Q): ${NC}" "$count" >&2
        else
            printf "${BOLD}Select target to scan (e.g. 1, 1,2, 1-%d, A, Q): ${NC}" "$count" >&2
        fi
        if ! read -r choice; then
            echo -e "\n${YELLOW}End of input, scan cancelled.${NC}" >&2
            exit 0
        fi
        choice=$(trim "$choice")

        case "$choice" in
            [aA]|[aA][lL][lL])
                SCAN_TARGETS=("${DISCOVERED_PATHS[@]}")
                return 0
                ;;
            [rR]|[rR][oO][oO][tT])
                if [[ -n "$parent_root" && -d "$parent_root" ]]; then
                    SCAN_TARGETS=("$parent_root")
                    return 0
                fi
                echo -e "  ${RED}Invalid selection. Please enter a valid number or option.${NC}" >&2
                ;;
            [qQ]|[qQ][uU][iI][tT]|[eE][xX][iI][tT])
                echo -e "${YELLOW}Scan cancelled.${NC}" >&2
                exit 0
                ;;
            "")
                echo -e "  ${YELLOW}Please enter a selection (1-${count}, A for all, or Q to quit).${NC}" >&2
                ;;
            *)
                local indices=()
                local idx_line
                if idx_line=$(parse_selection_indices "$choice" "$count"); then
                    while IFS= read -r idx; do
                        [[ -n "$idx" ]] && indices+=("$idx")
                    done <<< "$idx_line"
                    for idx in "${indices[@]}"; do
                        SCAN_TARGETS+=("${DISCOVERED_PATHS[$idx]}")
                    done
                    return 0
                else
                    echo -e "  ${RED}Invalid selection '${choice}'. Choose between 1-${count} (e.g. 1 or 1,2), A, or Q.${NC}" >&2
                fi
                ;;
        esac
    done
}
