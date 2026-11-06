#!/usr/bin/env bash
# Git integration for Advanced Webshell Scanner

# ============================================================================
# GIT UTILITIES
# ============================================================================
is_git_repo() {
    git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1
}

get_git_changed_files() {
    local files=()
    local f

    if [[ "$GIT_CHANGED_ONLY" == "true" ]]; then
        while IFS= read -r f; do
            [[ -n "$f" ]] && files+=("$f")
        done < <(
            git -C "$PROJECT_ROOT" diff --name-only 2>/dev/null
            git -C "$PROJECT_ROOT" diff --cached --name-only 2>/dev/null
            git -C "$PROJECT_ROOT" ls-files --others --exclude-standard 2>/dev/null
        )
    elif [[ -n "$GIT_SINCE_COMMIT" ]]; then
        while IFS= read -r f; do
            [[ -n "$f" ]] && files+=("$f")
        done < <(git -C "$PROJECT_ROOT" diff --name-only "$GIT_SINCE_COMMIT" 2>/dev/null)
    elif [[ -n "$GIT_DIFF" ]]; then
        while IFS= read -r f; do
            [[ -n "$f" ]] && files+=("$f")
        done < <(git -C "$PROJECT_ROOT" diff --name-only "$GIT_DIFF" 2>/dev/null)
    fi
    
    # Filter to existing files only
    local existing=()
    for f in "${files[@]}"; do
        [[ -f "$PROJECT_ROOT/$f" ]] && existing+=("$f")
    done
    
    printf '%s\n' "${existing[@]}"
}

get_git_history_files() {
    local since_date="${GIT_SINCE_DATE:-30 days ago}"
    local files=()
    
    # Get all files modified in history since date
    local files=()
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] && files+=("$f")
    done < <(git -C "$PROJECT_ROOT" log --since="$since_date" --name-only --pretty=format: 2>/dev/null | sort -u | grep -v '^$')
    
    # Filter to existing files
    local existing=()
    for f in "${files[@]}"; do
        [[ -f "$PROJECT_ROOT/$f" ]] && existing+=("$f")
    done
    
    printf '%s\n' "${existing[@]}"
}

get_file_git_info() {
    local file="$1"
    local rel_file="${file#$PROJECT_ROOT/}"
    
    local info="{"
    info+="\"file\":\"$(json_escape "$rel_file")\","
    
    # Last commit
    local last_commit
    last_commit=$(git -C "$PROJECT_ROOT" log -1 --format="%H|%an|%ae|%ad|%s" -- "$rel_file" 2>/dev/null || echo "")
    if [[ -n "$last_commit" ]]; then
        IFS='|' read -r hash author email date subject <<< "$last_commit"
        info+="\"last_commit\":{\"hash\":\"$hash\",\"author\":\"$(json_escape "$author")\",\"email\":\"$email\",\"date\":\"$date\",\"subject\":\"$(json_escape "$subject")\"},"
    else
        info+="\"last_commit\":null,"
    fi
    
    # Blame info (who added suspicious lines)
    local blame
    blame=$(git -C "$PROJECT_ROOT" blame --line-porcelain "$rel_file" 2>/dev/null | head -100 || echo "")
    if [[ -n "$blame" ]]; then
        local authors
        authors=$(echo "$blame" | grep "^author " | sort | uniq -c | sort -rn | head -5 | sed 's/^ *\([0-9]*\) author \(.*\)$/\2 (\1)/')
        info+="\"top_contributors\":[$(echo "$authors" | sed 's/[^)]*)/&/g' | sed 's/, $//' | awk '{print "\""$0"\""}' | paste -sd,),"
    else
        info+="\"top_contributors\":[],"
    fi
    
    # Is file in .gitignore?
    local ignored=false
    git -C "$PROJECT_ROOT" check-ignore "$rel_file" >/dev/null 2>&1 && ignored=true
    info+="\"ignored\":$ignored"
    
    info+="}"
    echo "$info"
}

get_repo_info() {
    local info="{"
    info+="\"root\":\"$(json_escape "$PROJECT_ROOT")\","
    
    # Current branch
    local branch
    branch=$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    info+="\"branch\":\"$branch\","
    
    # Remote URL
    local remote
    remote=$(git -C "$PROJECT_ROOT" config --get remote.origin.url 2>/dev/null || echo "")
    info+="\"remote\":\"$(json_escape "$remote")\","
    
    # Last commit
    local last_commit
    last_commit=$(git -C "$PROJECT_ROOT" log -1 --format="%H|%an|%ad|%s" 2>/dev/null || echo "")
    if [[ -n "$last_commit" ]]; then
        IFS='|' read -r hash author date subject <<< "$last_commit"
        info+="\"last_commit\":{\"hash\":\"$hash\",\"author\":\"$(json_escape "$author")\",\"date\":\"$date\",\"subject\":\"$(json_escape "$subject")\"}"
    else
        info+="\"last_commit\":null"
    fi
    
    info+="}"
    echo "$info"
}

# ============================================================================
# GIT HISTORY SCANNING
# ============================================================================
scan_git_history() {
    local since_date="${GIT_SINCE_DATE:-30 days ago}"
    local commits=()
    local commit_line
    while IFS= read -r commit_line; do
        [[ -n "$commit_line" ]] && commits+=("$commit_line")
    done < <(git -C "$PROJECT_ROOT" log --since="$since_date" --format="%H" --reverse 2>/dev/null)

    log "INFO" "Scanning ${#commits[@]} commits since $since_date"
    
    local results=()
    for commit in "${commits[@]}"; do
        # Get files changed in this commit
        local files=()
        local changed
        while IFS= read -r changed; do
            [[ -n "$changed" ]] && files+=("$changed")
        done < <(git -C "$PROJECT_ROOT" diff --name-only "$commit^..$commit" 2>/dev/null)
        
        for file in "${files[@]}"; do
            [[ -f "$PROJECT_ROOT/$file" ]] || continue
            should_scan_file "$PROJECT_ROOT/$file" || continue
            
            # Get commit info
            local commit_info
            commit_info=$(git -C "$PROJECT_ROOT" log -1 --format="%H|%an|%ad|%s" "$commit" 2>/dev/null)
            IFS='|' read -r hash author date subject <<< "$commit_info"
            
            results+=("{\"commit\":\"$hash\",\"author\":\"$(json_escape "$author")\",\"date\":\"$date\",\"subject\":\"$(json_escape "$subject")\",\"file\":\"$file\"}")
        done
    done
    
    # Output as JSON array
    local json="["
    local first=true
    for r in "${results[@]}"; do
        [[ "$first" == "true" ]] && first=false || json+=","
        json+="$r"
    done
    json+="]"
    echo "$json"
}