# Claude Code enforcement hook (optional)

The actionGuard skill tells the agent what to do. This hook makes Claude Code enforce the two rules that matter most, even if the agent forgets:

| Command | Hook decision |
|---|---|
| Forbidden (for example `rm -rf ~`, `git push --force origin main`) | **deny**: the command does not run, and the agent is told why |
| Tier 3 (for example `git push`, `terraform apply`, `DROP TABLE`) | **ask**: Claude Code shows an approval prompt, even if a permission rule would otherwise allow it |
| Tier 1 and Tier 2 | no decision: Claude Code's normal permission rules apply |

The hook never approves anything by itself, so it can only make Claude Code stricter. It covers the Bash and PowerShell tools. If the classifier fails, it prints a warning and defers to the normal permissions, so a bug cannot lock you out.

## Install

Add this to `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project), adjusting the path to where the skill is installed:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/skills/action-guard/integrations/claude-code/pretooluse.py" }
        ]
      }
    ]
  }
}
```

On Windows, use the full path with forward slashes, and `python` or `py -3` if `python3` isn't available, for example:
`"command": "python C:/Users/you/.claude/skills/action-guard/integrations/claude-code/pretooluse.py"`.

Restart Claude Code after editing settings. To check it, ask the agent to run `git push --force origin main` in a scratch repository: the hook should deny it.

## Tested

Verified with Claude Code 2.1.312 on Windows 11 (non-interactive `claude -p` runs with Bash allowed by permission rules):

- `git status` ran normally;
- `git push origin main` was held for approval and did not run;
- `git push --force origin main` was denied with the actionGuard reason.

In one run, the agent (which also had the actionGuard skill installed) declined to attempt the force-push at all, so the skill stopped it before the hook was needed. The hook's denial was then confirmed in a separate run where the agent did attempt it.

## Other agents

Any agent with a pre-execution hook can use the same classifier:

```
python3 scripts/guard.py classify -- '<command>'     # one quoted argument
# exit 0 = Tier 1, 2 = Tier 2, 3 = Tier 3 (require approval), 4 = forbidden (block)
```

Add `--json` for a machine-readable result.
