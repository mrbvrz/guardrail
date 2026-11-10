# THREATSCAN - Professional Threat Scanner v2.0

Enterprise-grade PHP security scanner with YARA rules, entropy analysis, heuristic scoring, and CI/CD integration.

## 🚀 Advanced Features

| Feature | Description |
|---------|-------------|
| **YARA Rules Engine** | Industry-standard malware signatures |
| **Entropy Analysis** | Detect encrypted/obfuscated payloads |
| **Heuristic Scoring** | ML-like scoring based on multiple signals |
| **Parallel Scanning** | Multi-threaded for large codebases |
| **Git-Aware** | Scan only changed files, track history |
| **SARIF Output** | IDE/SAST integration (GitHub Code Scanning) |
| **HTML Dashboard** | Visual reports with drill-down |
| **Quarantine Mode** | Auto-isolate suspicious files |
| **Config File** | YAML/JSON configuration |
| **Plugin System** | Custom detection rules |
| **Incremental Scan** | Cache-based for speed |
| **Threat Intel** | Hash lookup (VT, MalwareBazaar) |

## Installation

```bash
# Basic (bash only - no deps)
./threatscan.sh /path/to/project

# Advanced (requires: yara, php, jq, parallel)
brew install yara php jq parallel  # macOS
apt install yara php-cli jq parallel  # Ubuntu/Debian

# Verify
./threatscan.sh --check-deps
```

## Quick Start

```bash
# Full scan with all features
./threatscan.sh /var/www/html \
  --yara-rules ./rules \
  --entropy-threshold 7.5 \
  --heuristic-threshold 70 \
  --threads 4 \
  --output html,json,sarif \
  --quarantine ./quarantine \
  --config scan-config.yaml
```

## Configuration (scan-config.yaml)

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

  signatures:
    enabled: true
    database: "./signatures/webshells.ndb"

  github_actions:
    enabled: true
    fail_on: "HIGH"

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
  exclude_branches: ["main", "master", "release/*"]

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

## Advanced Usage

### 1. YARA Rules

```bash
# Download community rules
git clone https://github.com/YARA-Rules/rules.git ./rules/yara-rules

# Use custom rules
./threatscan.sh /project --yara-rules ./rules/yara-rules,./my-rules

# Compile rules for speed
./threatscan.sh --compile-yara ./rules -o ./compiled-rules.yarc
./threatscan.sh /project --yara-compiled ./compiled-rules.yarc
```

### 2. Entropy Analysis

```bash
# Scan for high-entropy (encrypted) content
./threatscan.sh /project --entropy-threshold 7.0

# Only specific extensions
./threatscan.sh /project --entropy-ext php,phtml,inc,module
```

### 3. Heuristic Scoring

Each file gets a risk score (0-100):

```
Score = Σ(weight_i × signal_i)

Signals:
  - Dangerous function calls (eval, exec, etc.)      weight: 15
  - Obfuscation patterns (base64, gzip, rot13)       weight: 20
  - User input to dangerous sinks                    weight: 25
  - File system operations with user input           weight: 15
  - Network operations (curl, fsockopen)             weight: 10
  - Suspicious strings (shell, backdoor, root)       weight: 10
  - High entropy sections                            weight: 5
  - YARA rule matches                                weight: 30 (bonus)
```

Thresholds:
- **0-30**: Clean
- **31-50**: Suspicious (review)
- **51-70**: Likely malicious
- **71-100**: Confirmed threat

### 4. Parallel Scanning

```bash
# Auto-detect CPU cores
./threatscan.sh /project --threads auto

# Specific thread count
./threatscan.sh /project --threads 8

# Progress output is on by default (phase lines + bar with rate/ETA)
./threatscan.sh /project --threads 4

# Silence it for scripting; findings only
./threatscan.sh /project --quiet
```

Progress goes to stderr, so stdout stays clean for piping. On a terminal the bar
is rewritten in place; redirected output gets a plain line every few seconds.

### 5. Git-Aware Scanning

```bash
# Scan only files changed since last commit
./threatscan.sh /project --git-changed

# Scan changes since specific commit
./threatscan.sh /project --git-since abc123

# Scan diff between branches
./threatscan.sh /project --git-diff main..feature

# Scan entire git history for introduced threats
./threatscan.sh /project --git-history --since "30 days ago"
```

### 6. Quarantine Mode

```bash
# Auto-quarantine HIGH/CRITICAL findings
./threatscan.sh /project --quarantine ./quarantine --quarantine-threshold HIGH

# Quarantine with password-protected ZIP
./threatscan.sh /project --quarantine ./quarantine --zip-password "custom123"

# Restore from quarantine
./threatscan.sh --restore-quarantine ./quarantine/file.php.quarantined
```

### 7. CI/CD Integration

**GitHub Actions:**
```yaml
- name: Advanced Webshell Scan
  uses: ./tools/threatscan
  with:
    path: .
    config: .github/webshell-config.yaml
    sarif: results.sarif
    fail-on: HIGH

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

**GitLab CI:**
```yaml
webshell_scan:
  script:
    - ./tools/threatscan.sh . --gitlab-ci --output json,sarif
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - webshell-report.html
    expire_in: 30 days
```

**Jenkins:**
```groovy
stage('Webshell Scan') {
    steps {
        sh './tools/threatscan.sh . --jenkins --output junit,html'
    }
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'webshell-report.html',
                reportName: 'Webshell Scan'
            ])
            junit 'reports/webshell-report.xml'
        }
    }
}
```

## Output Formats

### Console (Default)
```
╔══════════════════════════════════════════════════════════════╗
║  ADVANCED THREATSCAN v2.0                              ║
╚══════════════════════════════════════════════════════════════╝

[██████████████████████████████] 1247/1247 files (100%)

FILE                          SCORE  SEVERITY  FINDINGS
shell.php                     95     CRITICAL  YARA:webshell, Entropy:7.8, eval($_POST)
config.php.bak                72     HIGH      base64_decode(entropy:6.2), suspicious name
includes/utils.php            35     MEDIUM    3x base64_decode, 1x assert
vendor/legit/lib.php          12     CLEAN     -

Summary: 2 CRITICAL, 5 HIGH, 12 MEDIUM, 1228 CLEAN
```

### JSON
```json
{
  "scan_info": { "version": "2.0", "timestamp": "...", "duration_ms": 4523 },
  "summary": { "critical": 2, "high": 5, "medium": 12, "low": 0, "clean": 1228 },
  "findings": [
    {
      "file": "shell.php",
      "score": 95,
      "severity": "CRITICAL",
      "yara_matches": ["php_webshell_c99", "php_backdoor_generic"],
      "entropy": { "max": 7.8, "avg": 5.2, "sections": [...] },
      "heuristics": {
        "dangerous_functions": 8,
        "obfuscation": 3,
        "user_input_sinks": 4,
        "file_operations": 2,
        "suspicious_strings": 5
      },
      "signatures": ["c99shell", "WSO"],
      "lines": [15, 42, 87]
    }
  ]
}
```

### SARIF (for GitHub Code Scanning)
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "Webshell Scanner", "version": "2.0" }},
    "results": [
      {
        "ruleId": "WS002",
        "level": "error",
        "message": { "text": "eval() with user input detected" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "shell.php" },
            "region": { "startLine": 15 }
          }
        }]
      }
    ]
  }]
}
```

### HTML Dashboard
Interactive report with:
- Summary cards
- Severity distribution chart
- File explorer with risk scores
- Code viewer with highlighted findings
- YARA match details
- Entropy visualization
- Export to PDF

## Custom Rules (Plugin System)

Create `./rules/custom/webshell-php.yaml`:

```yaml
rules:
  - id: "custom_php_eval_chain"
    name: "Chained eval with encoding"
    severity: "CRITICAL"
    language: "php"
    pattern: |
      eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(
    description: "Nested encoding with eval - typical webshell obfuscation"
    tags: ["obfuscation", "eval", "webshell"]
    references:
      - "https://github.com/phosphor-security/webshell-signatures"

  - id: "custom_superglobal_direct_sink"
    name: "Direct superglobal to dangerous function"
    severity: "HIGH"
    language: "php"
    ast_pattern: |
      CallExpression[
        callee.name in ["eval", "exec", "system", "shell_exec", "passthru"]
        arguments[0].type == "Variable"
        arguments[0].name matches /\$_(GET|POST|REQUEST|COOKIE|SERVER)/
      ]
    description: "User input directly passed to execution function"

  - id: "custom_file_upload_bypass"
    name: "File upload extension bypass"
    severity: "HIGH"
    pattern: |
      \.(php|phtml|php[3-8])\.(jpg|jpeg|png|gif|pdf)
    description: "Double extension bypass attempt"
```

Load custom rules:
```bash
./threatscan.sh /project --custom-rules ./rules/custom
```

## Performance Tuning

```bash
# Large codebase (100k+ files)
./threatscan.sh /big-project \
  --threads 16 \
  --cache ./scan-cache \
  --incremental \
  --max-file-size 5MB \
  --skip-vendor \
  --yara-compiled ./compiled.yarc

# Memory-efficient
./threatscan.sh /project --stream-mode --batch-size 100

# Quick scan (signatures only)
./threatscan.sh /project --quick --signatures-only
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean |
| 1 | LOW/MEDIUM findings |
| 2 | HIGH findings |
| 3 | CRITICAL findings |
| 4 | YARA compilation error |
| 5 | Config error |
| 255 | Runtime error |

## Directory Structure

```
tools/threatscan/
├── threatscan.sh       # Main script
├── lib/
│   ├── scanner.sh                  # File discovery and filtering
│   ├── batch.sh                    # Batch scanning, scoring, signatures
│   ├── yara.sh                     # YARA integration
│   ├── entropy.sh                  # Entropy calculation
│   ├── heuristic.sh                # Heuristic scoring
│   ├── git.sh                      # Git integration
│   ├── quarantine.sh               # Quarantine handling
│   ├── output.sh                   # console/json/sarif/html/junit writers
│   └── utils.sh                    # Logging, helpers, progress
├── rules/
│   ├── yara/                       # YARA rule files
│   ├── signatures/                 # Signature databases
│   └── custom/                     # Custom rules
├── templates/
│   └── dashboard.html              # Generated on first HTML run if absent
├── config/
│   └── default.yaml                # Default configuration
└── logs/
```

## Requirements

| Tool | Version | Required For |
|------|---------|--------------|
| bash | 3.2+ | Core (4.0+ recommended) |
| jq | 1.6+ | **Required**: every result and report is built with jq |
| awk | POSIX | **Required**: entropy and float comparisons (no `bc` needed) |
| find, grep, sed, stat, file | POSIX | Core |
| yara | 4.0+ | Built-in and custom YARA rules |
| yarac | 4.0+ | Optional: precompiled rules (falls back to per-file rule scanning) |
| php | 7.4+ | Optional: AST parsing, syntax validation |
| parallel | 2020+ | Optional: only used when requested |
| git | 2.0+ | Git-aware features |
| clamscan | 0.103+ | Optional: AV scanning |

Run `./threatscan.sh --check-deps` to verify a host. On Ubuntu/Debian the
minimum install is:

```bash
sudo apt install jq yara   # awk, find, grep, sed ship with the base system
```

## License

MIT - Use freely in commercial and open-source projects.