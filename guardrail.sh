#!/usr/bin/env bash
#
# Guardrail — Unified CLI Orchestrator
# Operational security, server migration & web threat assessment suite.
#
# Usage:
#   ./guardrail.sh                              # Interactive module selector
#   ./guardrail.sh scan [args...]               # Run ThreatScan directly
#   ./guardrail.sh validate [args...]           # Run migration-validate directly
#   ./guardrail.sh harden [args...]             # Run hardening-check directly
#   ./guardrail.sh cve [args...]                # Run cve-check directly
#   ./guardrail.sh self-test                    # Run self-tests across all modules
#   ./guardrail.sh --check-deps                 # Verify all host dependencies
#

set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Color helpers
if [ -t 1 ]; then
    G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; C=$'\033[36m'; M=$'\033[35m'; N=$'\033[0m'
else
    G=''; R=''; Y=''; B=''; C=''; M=''; N=''
fi

print_banner() {
    cat << EOF
${C}${B}
╔════════════════════════════════════════════════════════════════════════════╗
║                           🛡️  G U A R D R A I L                            ║
║       Migration Integrity • Security Hardening • CVEs • ThreatScan         ║
╚════════════════════════════════════════════════════════════════════════════╝
${N}
EOF
}

usage() {
    print_banner
    cat << EOF
${B}Usage:${N} $0 [command] [options...]

${B}Direct Subcommands:${N}
  ${C}scan${N}, ${C}threatscan${N}        Run ThreatScan web root & malware scanner
  ${C}validate${N}, ${C}migration${N}      Run migration-validate (rsync folder integrity)
  ${C}harden${N}, ${C}hardening${N}        Run hardening-check benchmark & audit
  ${C}cve${N}, ${C}cve-check${N}            Run CVE exposure assessment
  ${C}self-test${N}                Run built-in verification suite across all tools
  ${C}--check-deps${N}             Verify system dependencies for all modules
  ${C}-h${N}, ${C}--help${N}               Show this help message

${B}Examples:${N}
  $0                             # Open interactive selector
  $0 self-test                   # Verify all 4 tools
  $0 scan /var/www/html -i       # Interactive web project scan
  $0 harden --benchmark          # Run security hardening benchmark
  $0 cve --benchmark             # Run CVE benchmark
  $0 validate --server srv1      # Validate migrated files for srv1
EOF
}

check_all_deps() {
    print_banner
    echo "${B}Checking system dependencies for all Guardrail tools:${N}"
    echo ""
    echo "${C}[*] ThreatScan Dependencies:${N}"
    bash "${SCRIPT_DIR}/threatscan/threatscan.sh" --check-deps || true
    echo ""
    echo "${C}[*] Core Audit Tools (find, awk, grep, sed, ssh, rsync, jq):${N}"
    local missing=()
    for cmd in find awk grep sed date ssh rsync jq; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo -e "  ${G}✓ $cmd found${N}"
        else
            echo -e "  ${R}✗ Missing: $cmd${N}"
            missing+=("$cmd")
        fi
    done
    echo ""
    if [ ${#missing[@]} -eq 0 ]; then
        echo "${G}${B}✓ All primary dependencies are satisfied.${N}"
        return 0
    else
        echo "${R}${B}✗ Some dependencies are missing: ${missing[*]}${N}"
        return 1
    fi
}

run_all_self_tests() {
    print_banner
    echo "${B}Executing self-tests across all Guardrail modules:${N}"
    echo ""

    local fail=0
    echo "${C}${B}[1/4] Testing ThreatScan...${N}"
    if bash "${SCRIPT_DIR}/threatscan/threatscan.sh" --self-test; then
        echo "${G}✓ ThreatScan OK${N}"
    else
        echo "${R}✗ ThreatScan FAILED${N}"
        fail=1
    fi
    echo ""

    echo "${C}${B}[2/4] Testing CVE Check...${N}"
    if bash "${SCRIPT_DIR}/cve-check/cve-check.sh" --self-test; then
        echo "${G}✓ CVE Check OK${N}"
    else
        echo "${R}✗ CVE Check FAILED${N}"
        fail=1
    fi
    echo ""

    echo "${C}${B}[3/4] Testing Hardening Check...${N}"
    if bash "${SCRIPT_DIR}/hardening-check/hardening-check.sh" --self-test; then
        echo "${G}✓ Hardening Check OK${N}"
    else
        echo "${R}✗ Hardening Check FAILED${N}"
        fail=1
    fi
    echo ""

    echo "${C}${B}[4/4] Testing Migration Validate...${N}"
    if bash "${SCRIPT_DIR}/migration-validate/migration-validate.sh" --self-test; then
        echo "${G}✓ Migration Validate OK${N}"
    else
        echo "${R}✗ Migration Validate FAILED${N}"
        fail=1
    fi
    echo ""

    if [ $fail -eq 0 ]; then
        echo "${G}${B}═══════════════════════════════════════════════════════════════════════${N}"
        echo "${G}${B}  ALL MODULE SELF-TESTS PASSED SUCCESSFULLY!${N}"
        echo "${G}${B}═══════════════════════════════════════════════════════════════════════${N}"
        return 0
    else
        echo "${R}${B}═══════════════════════════════════════════════════════════════════════${N}"
        echo "${R}${B}  SOME MODULE TESTS FAILED.${N}"
        echo "${R}${B}═══════════════════════════════════════════════════════════════════════${N}"
        return 1
    fi
}

interactive_menu() {
    print_banner
    echo "${B}Select a module or action to execute:${N}"
    echo ""
    echo "  ${C}${B}[1]${N} ${B}ThreatScan${N}             - Scan web roots for webshells, malware & backdoors"
    echo "  ${C}${B}[2]${N} ${B}Migration Validate${N}     - Compare and audit rsync migration folder by folder"
    echo "  ${C}${B}[3]${N} ${B}Hardening Check${N}        - Benchmark server configuration (SSH, FW, PHP, TLS, DB)"
    echo "  ${C}${B}[4]${N} ${B}CVE Check${N}              - Check distro security updates & known vulnerabilities"
    echo "  ──────────────────────────────────────────────────────────────────────────────"
    echo "  ${G}${B}[T]${N} ${B}Self-Test All${N}          - Run internal self-tests across all 4 tools"
    echo "  ${Y}${B}[D]${N} ${B}Check Dependencies${N}     - Check installed dependencies on this host"
    echo "  ${R}${B}[Q]${N} ${B}Quit${N}"
    echo ""

    local choice
    printf "${B}Enter choice [1-4, T, D, Q]: ${N}"
    read -r choice
    case "$choice" in
        1|scan|threatscan)
            echo ""
            bash "${SCRIPT_DIR}/threatscan/threatscan.sh"
            ;;
        2|validate|migration)
            echo ""
            bash "${SCRIPT_DIR}/migration-validate/migration-validate.sh" "$@"
            ;;
        3|harden|hardening)
            echo ""
            bash "${SCRIPT_DIR}/hardening-check/hardening-check.sh" --benchmark
            ;;
        4|cve|cve-check)
            echo ""
            bash "${SCRIPT_DIR}/cve-check/cve-check.sh" --benchmark
            ;;
        [tT]|test|self-test)
            run_all_self_tests
            ;;
        [dD]|deps|dependencies)
            check_all_deps
            ;;
        [qQ]|quit|exit|"")
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "${R}Invalid option: $choice${N}" >&2
            exit 2
            ;;
    esac
}

# Subcommand routing
if [ $# -eq 0 ]; then
    interactive_menu
    exit $?
fi

case "$1" in
    scan|threatscan)
        shift
        exec bash "${SCRIPT_DIR}/threatscan/threatscan.sh" "$@"
        ;;
    validate|migration|migration-validate)
        shift
        exec bash "${SCRIPT_DIR}/migration-validate/migration-validate.sh" "$@"
        ;;
    harden|hardening|hardening-check)
        shift
        exec bash "${SCRIPT_DIR}/hardening-check/hardening-check.sh" "$@"
        ;;
    cve|cve-check)
        shift
        exec bash "${SCRIPT_DIR}/cve-check/cve-check.sh" "$@"
        ;;
    self-test|--self-test)
        run_all_self_tests
        exit $?
        ;;
    --check-deps|-check-deps)
        check_all_deps
        exit $?
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        echo "${R}Unknown command: $1${N}" >&2
        usage >&2
        exit 2
        ;;
esac
