# Migration Validate Tool

A Bash script to validate rsync migration results from a source server to a destination server, per folder. Supports multiple server profiles, checksum verification, colored output, TUI dashboard, and automatic logging.

## Features

- **Multi-server profiles** — define hosts, paths, and folders in `profiles.conf`
- **Standard & deep validation** — quick (size + time) or thorough (checksum) modes
- **Flexible folder mapping** — handle different folder names on source vs destination
- **Colored output** — works with pipes/tee via `--color`
- **TUI dashboard** — compact real-time progress + summary with `--tui`
- **Auto-logging** — saves results to `result/migration-<profile>-<timestamp>.log` by default
- **Custom output** — `--output` / `-o` for custom log file
- **Self-test** — `--self-test` validates config parser without touching servers
- **Zero dependencies** — pure Bash + standard Linux tools (ssh, rsync, find, awk, etc.)

---

## Quick Start

```bash
# 1. Copy profiles.conf.example to profiles.conf and edit
cp profiles.conf.example profiles.conf
vim profiles.conf

# 2. Test config
bash migration-validate.sh --self-test
bash migration-validate.sh --list

# 3. Run validation (on DESTINATION server, as root)
sudo bash migration-validate.sh --server srv1
# Output saved to result/migration-srv1-<timestamp>.log

# 4. With TUI dashboard
sudo bash migration-validate.sh --server srv1 --tui

# 5. With forced colors (for pipes/tee)
sudo bash migration-validate.sh --server srv1 --color | tee migration.log

# 6. Deep validation (checksum)
sudo bash migration-validate.sh --server srv1 --deep
```

---

## Requirements

- **Run on DESTINATION server** as root (sudo)
- SSH key from destination root → source server works without password:
  ```bash
  ssh-copy-id root@source-server
  ssh root@source-server 'echo ok'
  ```
- Standard tools on both servers: `ssh`, `rsync`, `find`, `awk`, `du`, `df`, `date`
- `rsync` available on **both** source and destination
- `numfmt` (GNU coreutils) optional — fallback uses `awk`

---

## Configuration (`profiles.conf`)

One line per server:

```
name|host|source_path|dest_path|folder1,folder2,...
```

| Field | Description |
|-------|-------------|
| `name` | Profile label, used with `--server <name>` |
| `host` | `user@ip` (SSH key for root must work) |
| `source_path` | Webroot path on source server |
| `dest_path` | Webroot path on destination server |
| `folder` | Comma-separated. Use `src=dst` if names differ |

Example:
```
# name   | host           | source_path              | dest_path    | folders
srv1|root@10.0.0.1|/var/www/html      |/var/www/html|app1,app2,app3
srv2|root@10.0.0.2|/home/user/public_html|/var/www/html|public_html=web
```

- Lines starting with `#` are comments (ignored)
- Spaces around `|` are auto-trimmed

### Folder Mapping

If source folder name differs from destination:
```
src=dst
```
Example: source has `public_html`, destination should be `web`:
```
srv2|root@10.0.0.2|/home/user|/var/www/html|public_html=web
```
Script reads `/home/user/public_html` on source, compares with `/var/www/html/web` on destination.

---

## Usage

### List Profiles
```bash
bash migration-validate.sh --list
```

### Validate All Folders in Profile
```bash
sudo bash migration-validate.sh --server srv1
```

### Validate Specific Folders (override profile)
```bash
sudo bash migration-validate.sh --server srv1 app1 app2
```

### Deep Validation (checksum)
```bash
sudo bash migration-validate.sh --server srv1 --deep
```
Use once after final cut-over for data integrity assurance.

### TUI Dashboard
```bash
sudo bash migration-validate.sh --server srv1 --tui
```
Shows live progress per folder and a summary dashboard at the end.

### Force Colors (for pipes/tee)
```bash
sudo bash migration-validate.sh --server srv1 --color | tee migration.log
```

### Custom Output File
```bash
sudo bash migration-validate.sh --server srv1 -o /var/log/migration-srv1.log
sudo bash migration-validate.sh --server srv1 --output /var/log/migration-srv1.log
```

### Without Config File (legacy mode)
```bash
sudo HOST=root@10.0.0.5 SRC=/path/source DST=/path/dest \
     bash migration-validate.sh folder1 folder2
```
Environment variables override profile values.

---

## Output Modes

| Mode | Output | Use Case |
|------|--------|----------|
| Default | Terminal + auto-log (`result/migration-<profile>-<timestamp>.log`) | Standard runs |
| `--color` | Colored terminal + auto-log | When piping to `tee`/`less` |
| `--tui` | Compact dashboard + auto-log | Interactive monitoring |
| `-o file` | Terminal + custom log file | Custom log location |

---

## Reading Results

1. **Per folder** — table: Files, Symlinks, Folders, Bytes (source vs dest), rsync diffs
2. **Result** — `COMPLETE` (all match) or `NEEDS REVIEW` (differences found)
3. **Summary** — totals across all folders
4. **Destination storage** — partition capacity, usage, per-folder breakdown with ASCII graph
4. **Exit codes**:
   - `0` = all folders complete
   - `1` = some folders need review
   - `2` = usage/config/SSH error

---

## Re-run rsync for Differences

```bash
sudo rsync -avhP -e ssh root@source:/path/source/<folder>/ /path/dest/<folder>/
```
Small diffs often come from logs/cache/uploads changing on source during transfer.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Cannot SSH to ...` | Key not installed / wrong IP | `ssh-copy-id root@IP`, test `ssh root@IP 'echo ok'` |
| `Profile 'x' not found` | Wrong profile name | `bash migration-validate.sh --list` |
| `Profile 'x' incomplete` | Malformed config line | Ensure 5 fields separated by `|` |
| `Folder list empty` | No folders in profile/CLI | Add folders to config or CLI |
| `Source folder not found` | Wrong source path | Check `source_path` in profile |
| `Dest folder not found` | rsync not run yet / wrong path | Run rsync first, check `dest_path` |
| `rsync: command not found` | rsync missing on source | Install rsync on source server |

---

## File Structure

```
tools/
├── migration-validate.sh    # Main script (v3)
├── profiles.conf            # Server profiles (edit this)
├── README.md                # This file
└── result/                  # Auto-created for logs
    ├── migration-srv1-20261030-120000.log
    └── ...
```

---

## Security Notes

- Script only **reads** source (rsync dry-run `-n`), never modifies source
- `--delete` only active in dry-run, no files deleted
- All access via SSH key root; rotate credentials after cut-over
- Don't copy executables from source without malware scan first

---

## License

Internal tool for DPMPTSP Pekanbaru migration. Author: Hasan Suryaman — https://mrbvrz.web.id