# Audit log format

actionGuard records classified actions as JSON Lines, one object per line, in `.actionguard/audit.jsonl` at the repository root (or the current folder outside a repository). The folder is added to `.git/info/exclude`, so it is never committed. Append-only: never edit or delete earlier lines.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `ts` | yes (added automatically) | UTC time, ISO 8601 |
| `session` | yes (added automatically) | Groups the entries of one working session |
| `action` | yes | The exact command, request or browser step |
| `tier` | yes | 1, 2 or 3 |
| `decision` | yes | `auto`, `approved`, `denied`, `blocked` or `skipped` |
| `kind` | no | `shell` (default), `file`, `http`, `browser`, `db`, `other` |
| `forbidden` | no | `true` if it matched the forbidden list |
| `intent` | Tier 2 and 3 | Why it was needed |
| `affects` | Tier 2 and 3 | Files, systems, environments or people affected |
| `reversibility` | Tier 2 and 3 | 0 to 3 (see the risk matrix) |
| `rollback` | Tier 3 | Backup, recorded SHA or undo command |
| `approval` | approved Tier 3 | The user's own words, quoted |
| `exit_code` | no | Result of the command |
| `note` | no | Anything a reviewer should know |

## Example

```json
{"ts": "2026-10-29T21:40:12+00:00", "session": "20261029-214001-a1b2c3", "action": "npm install zod", "tier": 2, "decision": "auto", "kind": "shell", "intent": "add input validation", "affects": "package.json, package-lock.json", "reversibility": "3", "exit_code": 0}
{"ts": "2026-10-29T21:52:40+00:00", "session": "20261029-214001-a1b2c3", "action": "git push origin main", "tier": 3, "decision": "approved", "kind": "shell", "intent": "publish the validation change", "affects": "github.com/acme/app main", "reversibility": "1", "rollback": "git revert 9f2c1ab", "approval": "user: 'yes, push it'", "exit_code": 0}
{"ts": "2026-10-29T21:55:03+00:00", "session": "20261029-214001-a1b2c3", "action": "git push --force origin main", "tier": 3, "decision": "blocked", "forbidden": true, "note": "offered: push to a new branch and open a PR"}
```

## Writing and reading

```
guard.py log --tier 2 --decision auto --action "npm install zod" --intent "add input validation" --affects "package.json"
guard.py audit          # Markdown table for review
guard.py audit --json   # raw entries
```

Manual mode (no Python): keep the same fields as rows of a Markdown table and show it at the end of the session.
