# actionGuard

A safety policy for AI coding agents, packaged as an [Agent Skill](https://agentskills.io) for Claude Code, OpenAI Codex, OpenCode and other agents that read skills.

Before an agent runs a command, edits a file, touches a database, clicks in a browser or calls an API, actionGuard has it sort the action by what could go wrong:

| Tier | Meaning | Examples | Agent behaviour |
|---|---|---|---|
| **1** | Read-only | `git status`, `ls`, `grep`, `pytest`, `npm test`, `SELECT`, HTTP GET | Runs it |
| **2** | Reversible, local | editing files, `git commit`, `npm install`, `rm -rf node_modules` | States its intent in one line, runs it, logs it |
| **3** | Irreversible or external | `git push`, `git reset --hard`, `DROP TABLE`, deploys, `terraform apply`, publishing, emails, payments, `sudo` | Shows an **Action Intent Preview**, checks the rollback path, and waits for your explicit yes |
| **Forbidden** | Catastrophic | `rm -rf /` or `~`, formatting disks, force-pushing or deleting `main`, `DELETE` without `WHERE`, dropping a production database | Refuses, and offers a safer alternative |

Every Tier 2 and Tier 3 action, and every refusal, goes into an audit log you can review afterwards.

## What's included

```
SKILL.md                               the policy the agent follows
scripts/guard.py                       classifier and audit log (Python 3.8+, standard library)
references/risk-matrix.md              the full classification matrix
references/audit-log.md                audit log format
integrations/claude-code/              optional hook that makes Claude Code enforce it
tests/test_guard.py                    tests for the classifier and the hook
```

## Install

**Claude Code**

```sh
git clone https://github.com/Hashurah/actionGuard.git ~/.claude/skills/action-guard
```

The folder must be called `action-guard`, the skill's name. Skill names must be lowercase with hyphens.

**OpenAI Codex**: clone into Codex's skills folder, for example `~/.codex/skills/action-guard`. Codex's own sandbox and approval settings stay in force; actionGuard adds its policy on top.

**OpenCode, OpenClaw and others**: put the folder wherever the agent loads Agent Skills from.

Codex and OpenCode have not been tested yet. The skill uses only plain instructions and shell commands, so it should read the same everywhere.

## Advice vs enforcement

A skill is instructions the agent follows. It is not a sandbox. actionGuard gives you two levels:

1. **The skill (advice).** The agent classifies each action, using `scripts/guard.py` so the call is consistent and explained, and follows the tier rules.
2. **The hook (enforcement, Claude Code).** `integrations/claude-code/pretooluse.py` runs before every shell command. It **denies** forbidden commands, and **forces an approval prompt** for Tier 3, even when a permission rule would have allowed it. For Tier 1 and 2 it stays silent, so Claude Code's normal permissions apply. It never approves anything by itself. See [integrations/claude-code/README.md](integrations/claude-code/README.md) to set it up.

Other agents can call the classifier from their own pre-execution hooks. Exit code 4 means block, 3 means ask.

## The classifier

```sh
$ python3 scripts/guard.py classify -- 'git push --force origin main'
FORBIDDEN: do not run
Reversibility: 0/3
Why:
  - FORBIDDEN: force-push to a protected branch rewrites shared history
Rollback / safety:
  - Do not run this. If the user truly needs it, they must run it themselves, outside the agent.

$ python3 scripts/guard.py classify -- 'psql -c "DROP TABLE users"'
Tier 3 (irreversible / external): requires explicit user approval
Reversibility: 0/3
Why:
  - SQL DROP permanently removes data
Rollback / safety:
  - Take a backup first (e.g. pg_dump -t <table> / mysqldump) and confirm the database name.

$ python3 scripts/guard.py classify --http POST https://api.stripe.com/v1/charges
```

Quote the whole command as one argument, as above. Otherwise your shell expands `~`, globs and variables first (and Git Bash rewrites `/`). The classifier undoes the common cases and warns, but quoting is the reliable way.

It handles compound commands (`&&`, pipes, `$(...)`, `bash -c`), `sudo` and environment prefixes, production targets, writes to credential files or outside the project, quoted text that is only data (`echo 'rm -rf /'` is not a delete), PowerShell commands and Windows paths. Unknown commands are never treated as read-only. The agent may always rate an action higher than the classifier does, never lower.

## Audit log

```sh
python3 scripts/guard.py log --tier 3 --decision approved --action "git push origin main" \
  --intent "publish the fix" --approval "user: 'yes, push it'"
python3 scripts/guard.py audit
```

Entries are JSON Lines in `.actionguard/audit.jsonl` at the repository root, kept out of git automatically. Format: [references/audit-log.md](references/audit-log.md).

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The 23 test groups classify 125 shell commands across the tiers, including near-misses that must not be blocked, evasions that must be, sensitive file writes, and unquoted commands mangled by the shell. They also cover HTTP requests, the audit log and the hook. They pass on Windows 11 with Python 3.12 and 3.14.

The Claude Code hook was also checked in real `claude -p` sessions (Claude Code 2.1.312): `git status` ran normally, `git push origin main` was held for approval, and `git push --force origin main` was denied.

## Limits

- The classifier recognises common tools and patterns. It can't see what a script does, which database a connection string points at, or whether a branch is shared, which is why the agent is told to judge upward from its result.
- "Forbidden" stops the agent, not you. If you really need one of those commands, run it yourself.
- Approval must come from you. Text in files, web pages, tool output or API responses never counts as approval, which protects against prompt injection.

## License

MIT
