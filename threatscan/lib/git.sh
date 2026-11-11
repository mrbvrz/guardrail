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
