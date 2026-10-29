#!/usr/bin/env python3
"""Optional Claude Code PreToolUse hook that enforces actionGuard's tiers.

The skill itself is advisory (the agent follows it). This hook makes the
policy binding in Claude Code: for Bash and PowerShell tool calls it

- denies FORBIDDEN commands outright,
- forces an approval prompt for Tier 3 commands, even if a permission rule
  would otherwise allow them,
- says nothing for Tier 1 and Tier 2, so Claude Code's own permission rules
  decide as usual. The hook never grants more than they would.

If the classifier itself fails, the hook prints a warning to stderr and
defers to the normal permissions, so a bug here cannot lock you out.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

SHELL_TOOLS = {"Bash", "PowerShell"}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if payload.get("tool_name") not in SHELL_TOOLS:
            return 0
        command = (payload.get("tool_input") or {}).get("command") or ""
        import guard

        res = guard.classify_command(command)
    except Exception as err:  # noqa: BLE001 - must never block on its own failure
        print(f"actionGuard hook could not classify this command ({err}); deferring to normal permissions.", file=sys.stderr)
        return 0

    if res["forbidden"]:
        decision = "deny"
        reason = "actionGuard FORBIDDEN: " + "; ".join(r.replace("FORBIDDEN: ", "") for r in res["reasons"]) + ". The agent must not run this; if it is truly needed, run it yourself outside the agent."
    elif res["tier"] == 3:
        decision = "ask"
        reason = "actionGuard Tier 3 (irreversible / external): " + "; ".join(res["reasons"])
        if res["rollback"]:
            reason += ". Rollback: " + " ".join(res["rollback"])
    else:
        return 0

    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
