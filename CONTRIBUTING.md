# Contributing

## Commit messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

- **type** — `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- **scope** — optional: `threatscan`, `hardening-check`, `cve-check`, `migration-validate`, `repo`, `docs`.
- **subject** — imperative mood, lowercase, no trailing period, 72 characters max.
- **body** — what changed and why, wrapped at 72 characters. Skip it when the subject is enough.
- **footer** — `BREAKING CHANGE: ...`, `Refs: #123` or `Closes: #123`.

### Examples

```
fix(migration-validate): honour folders passed on the command line
docs: document ThreatScan exit codes
chore(repo): ignore client engagement deliverables
```

### Rules

- One logical change per commit; keep unrelated fixes apart.
- Never commit client engagement data, real host addresses, credentials or scan output.
- No tool attribution, "generated with" lines or co-author trailers.

### Template

A message template ships with the repository:

```bash
git config commit.template .gitmessage
```

`--self-test` in every tool must pass before you commit a change to it.
