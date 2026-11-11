# 🛡️ THREATSCAN v2.0 — Enterprise Web & PHP Threat Scanner

Enterprise-grade PHP and web root security scanner featuring **automatic web directory discovery**, **interactive multi-project target selection**, **YARA rules**, **Shannon entropy analysis**, **heuristic risk scoring**, and **CI/CD reporting**.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🧭 **Auto-Discovery & Interactive Selector** | Automatically detects web roots from Nginx/Apache configs and `/var/www/html` sub-projects (`web-a`, `web-b`) with an interactive CLI picker |
| 🧬 **YARA Rules Engine** | Industry-standard malware and webshell signature matching |
| 📈 **Entropy Analysis** | Detects encrypted, packed, or heavily obfuscated payloads |
| 🧠 **Heuristic Scoring** | Multi-signal risk scoring (0–100) across dangerous sinks, obfuscation, and superglobals |
| ⚡ **Parallel Scanning** | Multi-threaded batch execution for large codebases |
| 🌿 **Git-Aware Modes** | Scan only uncommitted/changed files, branch diffs, or commit history |
| 📊 **HTML Dashboard & SARIF** | Interactive visual dashboard plus SARIF 2.1.0, JSON, and JUnit XML exports |
| 🔒 **Quarantine Mode** | Safely isolate suspicious files with metadata manifests and restoration support |
| 🌐 **Threat Intelligence** | Optional SHA-256 hash lookups via VirusTotal and MalwareBazaar |

---

## 🚀 Installation & Host Verification

```bash
# macOS (Homebrew)
brew install yara php jq parallel

# Ubuntu / Debian
sudo apt update && sudo apt install -y jq file findutils gawk yara php-cli parallel clamav

# Verify installed dependencies
./threatscan.sh --check-deps
```

---

## ⚡ Quick Start

### 1. Automatic Discovery & Interactive Selection

When run without a path or pointed at a parent web root (like `/var/www/html` containing `web-a` and `web-b`), ThreatScan automatically detects the projects, identifies their frameworks, and lets you choose which target(s) to scan:

```bash
# Auto-discover web folders across the system (Nginx, Apache, /var/www/html, etc.)
sudo ./threatscan.sh

# Scan /var/www/html — prompts to choose web-a, web-b, all (A), or parent root (R)
sudo ./threatscan.sh /var/www/html --output console,html,json

# List discovered web folders and exit without scanning
sudo ./threatscan.sh --list-targets
sudo ./threatscan.sh /var/www/html --list-targets

# Scan all discovered sub-projects sequentially without interactive prompts (CI/Cron)
sudo ./threatscan.sh /var/www/html --all-targets --output console,html,json

# Scan the parent directory as a single combined root without sub-project splitting
sudo ./threatscan.sh /var/www/html --no-subprojects
```

**Interactive Prompt Preview:**

```text
[*] Found 2 web project(s) under /var/www/html:

  [1] /var/www/html/web-a          (Laravel      • ~1,420 files • subfolder (/var/www/html))
  [2] /var/www/html/web-b          (WordPress    • ~3,810 files • subfolder (/var/www/html))
  ──────────────────────────────────────────────────────────────────────────────
  [A] Scan ALL projects sequentially (1-2)
  [R] Scan parent root directly as a single scan (/var/www/html)
  [Q] Quit

Select target to scan (e.g. 1, 1,2, 1-2, A, R, Q):
```

### 2. Full Scan with Custom Thresholds & Quarantine

```bash
./threatscan.sh /var/www/html \
  --yara-rules ./rules \
  --entropy-threshold 7.5 \
  --heuristic-threshold 70 \
  --threads 4 \
  --output console,html,json,sarif \
  --quarantine ./quarantine \
  --config config/default.yaml
```

---

## ⚙️ Configuration (`config/default.yaml`)

```yaml
scanner:
  threads: 4
  timeout: 300
  follow_symlinks: false
  max_file_size: 10MB

detection:
  yara:
    enabled: true
    rules_dir: "./rules"
    custom_rules: []
  
  entropy:
    enabled: true
    threshold: 7.5
    min_length: 100
    exclude_extensions: [".jpg", ".png", ".pdf", ".zip"]
  
  heuristics:
    enabled: true
    threshold: 70
    weights:
      dangerous_functions: 15
      obfuscation: 20
      user_input_sinks: 25
      file_operations: 15
      network_operations: 10
      suspicious_strings: 10
      entropy: 5

output:
  formats: ["console", "json", "sarif", "html"]
  output_dir: "./reports"
  html_template: "./templates/dashboard.html"

quarantine:
  enabled: false
  directory: "./quarantine"
  preserve_structure: true
  zip_password: "infected"

git:
  enabled: true
  scan_changed_only: false
  since_commit: ""

whitelist:
  paths:
    - "vendor/"
    - "node_modules/"
    - "storage/"
    - ".git/"
  patterns:
    - "*.min.js"
    - "*.bundle.js"
  files: []

threat_intel:
  enabled: false
  virustotal_api_key: ""
  malwarebazaar: true
  cache_ttl: 86400
```

---

## 🔬 Advanced Usage

### 🧬 1. YARA Rules

```bash
# Built-in YARA rules are used automatically when the yara binary is installed
./threatscan.sh /var/www/html

# Use multiple YARA rule directories
./threatscan.sh /var/www/html --yara-rules ./rules/yara,./custom-rules

# Pre-compile YARA rules for faster repeated scans
./threatscan.sh --compile-yara ./rules/yara --compile-yara-output ./compiled.yarc
./threatscan.sh /var/www/html --yara-compiled ./compiled.yarc

# Skip YARA entirely (no binary, or to isolate heuristic results)
./threatscan.sh /var/www/html --no-yara
```

### 📈 2. Entropy Analysis

```bash
# Adjust Shannon entropy threshold (0-8, default: 7.5)
./threatscan.sh /var/www/html --entropy-threshold 7.0 --entropy-min-length 100
```

### 🧠 3. Heuristic Scoring Model

Each scanned file receives a composite risk score (`0–100`):

```text
Score = Σ(weight_i × signal_i)

Signals:
  • Dangerous function calls (eval, exec, system, passthru)   weight: 15
  • Obfuscation patterns (base64, gzinflate, str_rot13, chr)  weight: 20
  • Direct user input to execution sinks ($_POST, $_GET)      weight: 25
  • Suspicious file system operations                         weight: 15
  • Network / socket operations (curl, fsockopen)             weight: 10
  • Known webshell strings & indicators                       weight: 10
  • High-entropy code blocks                                  weight:  5
  • YARA signature match bonus                                weight: 30
  • Built-in signature match bonus                            weight: 20
```

`--heuristic-threshold` (default: 70) only gates the heuristic part: a file whose
heuristic score is below it contributes no heuristic points. Signature, YARA and
entropy evidence is always scored, so a low heuristic score never hides a match.

**Severity Mapping:**
- 🟢 **0**: `CLEAN`
- 🔵 **1–29**: `INFO`
- 🟡 **30–49**: `LOW`
- 🟠 **50–69**: `MEDIUM`
- 🔴 **70–89**: `HIGH`
- 🚨 **90–100**: `CRITICAL`

### ⚡ 4. Parallel Execution & Progress Control

```bash
# Auto-detect CPU cores (default)
./threatscan.sh /var/www/html --threads auto

# Specify worker thread count
./threatscan.sh /var/www/html --threads 8

# Hide progress bar while keeping phase logs
./threatscan.sh /var/www/html --no-progress

# Quiet mode (findings only)
./threatscan.sh /var/www/html --quiet
```

### 🌿 5. Git-Aware Scanning

```bash
# Scan only uncommitted / modified files
./threatscan.sh /project --git-changed

# Scan changes since a specific commit
./threatscan.sh /project --git-since abc1234

# Scan diff between two branches or tags
./threatscan.sh /project --git-diff main..release-candidate
```

### 🔒 6. Quarantine Management

```bash
# Automatically isolate HIGH and CRITICAL findings
./threatscan.sh /var/www/html --quarantine ./quarantine --quarantine-threshold HIGH

# Restore a quarantined file to its original path
./threatscan.sh --restore-quarantine ./quarantine/20261110_150000_shell.php.quarantined
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
- name: Run ThreatScan
  run: |
    bash ./threatscan/threatscan.sh . \
      --no-subprojects \
      --output console,sarif \
      --output-dir ./reports \
      --fail-on HIGH

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ./reports
```

### GitLab CI

```yaml
threatscan:
  stage: test
  script:
    - bash ./threatscan/threatscan.sh . --no-subprojects --output console,json,html
  artifacts:
    paths:
      - threatscan/reports/
    expire_in: 30 days
```

---

## 📊 Output Formats

- 🖥️ **`console`** — Real-time progress bar, severity breakdown table, and top findings summary.
- 🌐 **`html`** — Standalone interactive dark/light security dashboard with search, severity filters, and code inspection modal.
- 📄 **`json`** — Machine-readable full report with per-file heuristics, entropy metrics, and scan metadata.
- 🛡️ **`sarif`** — SARIF v2.1.0 report compatible with GitHub Code Scanning and IDE security plugins.
- 🧪 **`junit`** — JUnit XML test suite output for Jenkins and CI test runners.

> When scanning multiple targets in one session (e.g. `web-a` and `web-b`), report filenames are automatically namespaced by project slug: `webshell-scan-web-a-<timestamp>.html`.

---

## 🚦 Exit Codes

| Exit Code | Status | Description |
| :---: | :--- | :--- |
| `0` | 🟢 **Clean / Pass** | No findings reached the `--fail-on` threshold (default: `HIGH`) |
| `1` | 🟡 **Low / Medium** | `LOW` or `MEDIUM` severity findings met the configured threshold |
| `2` | 🔴 **High** | `HIGH` severity findings detected |
| `3` | 🚨 **Critical** | `CRITICAL` severity findings detected |
| `4` | ⚠️ **YARA Error** | YARA rule compilation failure |
| `5` | ⚙️ **Config Error** | Configuration file parsing error |
| `255` | ❌ **Runtime Error** | Missing required dependency or invalid target directory |

---

## 🗂️ Directory Structure

```text
threatscan/
├── threatscan.sh          # Main CLI entrypoint & multi-target runner
├── lib/
│   ├── discovery.sh       # Web root auto-discovery, framework fingerprinting & interactive menu
│   ├── scanner.sh         # File discovery and content-type filtering
│   ├── batch.sh           # Parallel batch worker, signature & score aggregation
│   ├── yara.sh            # YARA rule compiler and runner
│   ├── entropy.sh         # Shannon entropy calculation
│   ├── heuristic.sh       # Heuristic pattern & AST risk analysis
│   ├── git.sh             # Git diff and history file resolvers
│   ├── quarantine.sh      # File isolation and restoration handlers
│   ├── output.sh          # Console, JSON, SARIF, HTML, and JUnit generators
│   └── utils.sh           # Logging, colors, float helpers, and progress bar
├── rules/
│   ├── yara/              # YARA signature rules (.yar)
│   └── signatures/        # Pattern signature databases
├── templates/
│   └── dashboard.html     # Interactive HTML report template
├── config/
│   └── default.yaml       # Default scanner configuration
├── reports/               # Generated scan reports (git-ignored)
└── logs/                  # Detailed execution logs (git-ignored)
```
