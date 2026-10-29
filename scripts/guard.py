#!/usr/bin/env python3
"""actionGuard: risk classifier and audit log for agent actions.

    guard.py classify [--json] -- <shell command>
    guard.py classify [--json] --http METHOD URL
    guard.py log --action "..." --tier N --decision auto|approved|denied|blocked|skipped [options]
    guard.py audit [--json]

classify exit codes: 0 = Tier 1, 2 = Tier 2, 3 = Tier 3, 4 = FORBIDDEN.

The classifier is deliberately conservative and explainable: every result
lists the rules that fired. Unknown commands are never Tier 1. It is a
second opinion, not a replacement for reading the command: the agent still
applies the policy in SKILL.md and can always classify *higher*, never lower.

Standard library only; Python 3.8+.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shlex
import subprocess
import sys
import uuid
from pathlib import Path

VERSION = "1.0.0"
LOG_DIR = ".actionguard"

HOME_DIR = os.path.expanduser("~")
TIER_NAMES = {1: "Tier 1 (read-only)", 2: "Tier 2 (reversible mutation)", 3: "Tier 3 (irreversible / external)"}
PROTECTED_BRANCHES = r"(?:main|master|production|prod|release|live|trunk)"
PROD_WORD = re.compile(r"(?<![\w-])(prod|production|live)(?![\w-])", re.I)
REGENERABLE = {
    "node_modules", "dist", "build", "out", ".next", ".nuxt", ".cache", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "target", "coverage", ".turbo", ".parcel-cache", "tmp", ".tmp", ".venv", "venv",
    "bin", "obj", ".gradle", ".angular", ".svelte-kit", "storybook-static", "test-results", "playwright-report",
}

# ------------------------------------------------------------- forbidden

_RM_TARGET = r"""(?:/\*?|~/?\*?|\$HOME/?|\$\{HOME\}/?|[A-Za-z]:[\\/]?\*?|/(?:bin|boot|dev|etc|home|lib|lib64|opt|proc|root|sbin|srv|sys|usr|var|System|Users|Library|Applications)/?)"""
# rm with any mix of short/long flags, then (possibly after other targets) a catastrophic target.
# Whether the flags include recursion is checked in _forbidden.
RM_ANY = re.compile(r"\brm((?:\s+(?:-[A-Za-z]+|--[a-z-]+))*)\s+(?:\S+\s+)*?" + _RM_TARGET + r"""(?=$|[\s'");&|])""")
RAW_ONLY = {"fork bomb"}  # matched against the raw text, since splitting would break it apart

FORBIDDEN = [
    (re.compile(r"\bRemove-Item\b.*-Recurse.*\s(?:[A-Za-z]:\\?|~|\$HOME|\$env:USERPROFILE)(?=$|[\s'\"])", re.I),
     "recursive delete of a drive root or the home directory"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb"),
    (re.compile(r"\bmkfs(\.\w+)?\b|\bFormat-Volume\b|\bformat\s+[A-Za-z]:", re.I), "formats a disk"),
    (re.compile(r"\bdd\b.*\bof=/dev/(sd|hd|nvme|disk|mmcblk|xvd)"), "overwrites a raw disk device"),
    (re.compile(r">\s*/dev/(sd|hd|nvme|disk|mmcblk)"), "writes directly to a disk device"),
    (re.compile(r"\bch(mod|own)\s+(-[A-Za-z]*R[A-Za-z]*|--recursive)\s+\S+\s+/(\s|$)"), "recursively changes permissions on the filesystem root"),
    (re.compile(r"\bgit\s+push\b(?=.*\s(-f|--force|--force-with-lease|--force-if-includes)\b)(?=.*(?:\s|:|refs/heads/)" + PROTECTED_BRANCHES + r"(?=$|\s))"),
     "force-push to a protected branch rewrites shared history"),
    (re.compile(r"\bgit\s+push\b.*\s\+(?:refs/heads/|HEAD:)?" + PROTECTED_BRANCHES + r"(?=$|\s)"), "forced refspec to a protected branch rewrites shared history"),
    (re.compile(r"\bgit\s+push\b.*(?:--delete|\s-d)\s+(?:\S+\s+)?" + PROTECTED_BRANCHES + r"(?=$|\s)|\bgit\s+push\b.*\s:" + PROTECTED_BRANCHES + r"(?=$|\s)"),
     "deletes a protected branch on the remote"),
]
SQL_UNBOUNDED = re.compile(r"\b(DELETE\s+FROM|UPDATE)\s+[\w.\"`\[\]]+(?:\s+SET\b)?((?:(?!\bWHERE\b|;).)*)(;|$)", re.I | re.S)
SQL_DROP_PROD = re.compile(r"\bDROP\s+(DATABASE|SCHEMA)\s+(IF\s+EXISTS\s+)?[\"`]?\w*(prod|production|live)\w*", re.I)


# Commands whose quoted arguments are data (messages, search patterns), not code to run.
DATA_COMMANDS = {"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "cat", "head", "tail", "sed", "awk", "find", "write-output", "write-host", "select-string"}
DATA_GIT = {"commit", "log", "grep", "show", "tag", "notes", "stash"}
QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def _executable_text(text: str) -> str:
    """The command with quoted *data* blanked out: `echo 'rm -rf /'` deletes nothing.
    Quoted text given to shells, interpreters and database clients is kept, because it runs.
    Command substitutions inside quotes are classified separately (see classify)."""
    parts = []
    for seg, _ in split_segments(text):
        tk = strip_wrappers(tokens(seg))
        head = os.path.basename(tk[0]).lower() if tk else ""
        data = head in DATA_COMMANDS or (head == "git" and len(tk) > 1 and tk[1].lower() in DATA_GIT)
        parts.append(QUOTED.sub("''", seg) if data else seg)
    return " ; ".join(parts)


def _forbidden(raw: str):
    text = _executable_text(raw)
    hits = [why for rx, why in FORBIDDEN if rx.search(raw if why in RAW_ONLY else text)]
    for m in RM_ANY.finditer(text):
        if re.search(r"(?:^|\s)(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)(?=\s|$)", m.group(1)):
            hits.append("recursive delete of the filesystem root, the home directory or a system directory")
            break
    else:
        # The home directory spelled out, as the shell expands "~" before we see it.
        homes = {h.rstrip("/\\").lower() for h in (HOME_DIR, HOME_DIR.replace("\\", "/"))}
        for seg, _ in split_segments(text):
            tk = strip_wrappers(tokens(seg))
            if not tk or os.path.basename(tk[0]).lower() not in ("rm", "remove-item", "ri", "rmdir", "rd", "del"):
                continue
            recursive = any(re.match(r"^(-[A-Za-z]*[rR][A-Za-z]*|--recursive|-recurse|/s)$", a, re.I) for a in tk[1:])
            if recursive and any(a.rstrip("/\\").lower() in homes for a in tk[1:] if not a.startswith("-")):
                hits.append("recursive delete of the home directory")
                break
    for m in SQL_UNBOUNDED.finditer(text):
        verb = m.group(1).split()[0].upper()
        hits.append(f"{verb} without a WHERE clause affects every row in the table")
    if SQL_DROP_PROD.search(text):
        hits.append("drops a production database or schema")
    return hits


# ------------------------------------------------------------ splitting


def split_segments(cmd: str):
    """Split on unquoted && || ; | & and newlines. Returns (segment, piped_into)."""
    segs, cur, q, i = [], [], None, 0
    piped = []
    while i < len(cmd):
        c = cmd[i]
        nxt = cmd[i + 1] if i + 1 < len(cmd) else ""
        prev = cmd[i - 1] if i else ""
        if q:
            cur.append(c)
            if c == q:
                q = None
            elif c == "\\" and q == '"' and nxt:
                cur.append(nxt)
                i += 1
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c in ";\n" or (c == "&" and nxt == "&") or (c == "|" and nxt == "|"):
            segs.append(("".join(cur), False))
            cur = []
            if c in "&|":
                i += 1
        elif c == "|":
            segs.append(("".join(cur), False))
            cur = []
            piped.append(len(segs))
        elif c == "&" and prev != ">" and nxt != ">":
            segs.append(("".join(cur), False))
            cur = []
        else:
            cur.append(c)
        i += 1
    segs.append(("".join(cur), False))
    return [(s.strip(), idx in piped) for idx, (s, _) in enumerate(segs) if s.strip()]


def substitutions(cmd: str):
    out = re.findall(r"\$\(([^()]*(?:\([^()]*\)[^()]*)*)\)", cmd) + re.findall(r"`([^`]+)`", cmd)
    return [s for s in out if s.strip()]


def tokens(seg: str):
    """Split like a shell, but keep backslashes intact so Windows paths survive."""
    try:
        raw = shlex.split(seg, posix=False)
    except ValueError:
        raw = seg.split()
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"" else t for t in raw]


def strip_wrappers(tk):
    """Drop env assignments and prefixes such as sudo, time and nohup (no side effects)."""
    while tk:
        head = tk[0].lower()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tk[0]):
            tk = tk[1:]
        elif head in ("sudo", "doas", "time", "nohup", "nice", "exec", "command", "builtin", "env") and len(tk) > 1:
            tk = tk[1:]
            while tk and tk[0].startswith("-"):
                tk = tk[2:] if tk[0] in ("-u", "-g") else tk[1:]
        else:
            break
    return tk


WRITE_COMMANDS = {"cp", "mv", "tee", "touch", "ln", "install", "rsync", "copy-item", "move-item", "set-content", "add-content", "out-file", "new-item", "sed"}
SENSITIVE_NAME = re.compile(r"(^|[\\/])(\.env(\.[\w-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials(\.json)?|id_[a-z0-9]+(\.pub)?|authorized_keys|known_hosts|\.(bash|zsh)rc|\.bash_profile|\.profile|\.zprofile|\.gitconfig|Microsoft\.PowerShell_profile\.ps1)$", re.I)
TEMP_DIRS = re.compile(r"^(/tmp/|/var/tmp/|\$TMPDIR|\$env:TEMP|%TEMP%|[A-Za-z]:[\\/].*[\\/]Temp[\\/])", re.I)


def write_targets(seg: str, tk) -> list:
    """Paths a segment writes to: redirect targets and the arguments of file-writing commands."""
    bare = re.sub(r"'[^']*'|\"[^\"]*\"", "''", seg)
    targets = [m.group(1) for m in re.finditer(r"\d?>>?\s*([^\s&|;]+)", bare) if not m.group(1).startswith("&")]
    tk = strip_wrappers(tk)
    if tk and os.path.basename(tk[0]).lower() in WRITE_COMMANDS:
        args = [a for a in tk[1:] if not a.startswith("-")]
        if os.path.basename(tk[0]).lower() == "sed":
            args = args[1:]  # the first argument is the edit script, not a file
        targets += args
    return targets


def sensitive_write(path: str) -> str | None:
    """Why writing to this path is Tier 3, or None if it is an ordinary project write."""
    p = path.strip("'\"")
    if not p or p in ("/dev/null", "NUL", "$null"):
        return None
    if SENSITIVE_NAME.search(p.rstrip("/\\")) or re.search(r"(^|[\\/])\.(ssh|aws|kube|gnupg|docker|config[\\/]gcloud)([\\/]|$)", p):
        return f"writes to a credential, key or shell-profile file ({p})"
    if TEMP_DIRS.search(p):
        return None
    if p.startswith(("~", "$HOME", "${HOME}", "$env:USERPROFILE", "%USERPROFILE%")):
        return f"writes into the home directory ({p}), outside the project"
    if os.path.isabs(p) or re.match(r"^[A-Za-z]:[\\/]", p):
        try:
            inside = os.path.commonpath([os.path.abspath(p), os.getcwd()]) == os.getcwd()
        except ValueError:
            inside = False
        if not inside:
            return f"writes outside the project ({p})"
    return None


def has_write_redirect(seg: str) -> bool:
    bare = re.sub(r"'[^']*'|\"[^\"]*\"", "''", seg)
    for m in re.finditer(r"(\d?)(>>?)\s*(&?\S+)", bare):
        target = m.group(3)
        if target.startswith("&") or target in ("/dev/null", "NUL", "$null", "nul"):
            continue
        return True
    return False


# ---------------------------------------------------------------- result


class R:
    def __init__(self):
        self.tier = 1
        self.rev = 3
        self.reasons: list[str] = []
        self.rollback: list[str] = []
        self.forbidden = False

    def add(self, tier, rev, reason, rollback=None):
        if tier > self.tier:
            self.tier = tier
        self.rev = min(self.rev, rev)
        if reason not in self.reasons:
            self.reasons.append(reason)
        if rollback and rollback not in self.rollback:
            self.rollback.append(rollback)

    def merge(self, other: "R"):
        for reason in other.reasons:
            if reason not in self.reasons:
                self.reasons.append(reason)
        for rb in other.rollback:
            if rb not in self.rollback:
                self.rollback.append(rb)
        self.tier = max(self.tier, other.tier)
        self.rev = min(self.rev, other.rev)
        self.forbidden = self.forbidden or other.forbidden

    def as_dict(self, action, kind="shell"):
        return {
            "action": action,
            "kind": kind,
            "tier": self.tier,
            "tier_name": "FORBIDDEN" if self.forbidden else TIER_NAMES[self.tier],
            "forbidden": self.forbidden,
            "requires_approval": self.tier == 3 and not self.forbidden,
            "reversibility": 0 if self.forbidden else self.rev,
            "reasons": self.reasons,
            "rollback": self.rollback,
        }


# ------------------------------------------------------------- rules

READ_ONLY = {
    "ls", "dir", "cat", "type", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "pwd", "echo",
    "printf", "which", "where", "whoami", "id", "date", "env", "printenv", "wc", "sort", "uniq", "diff", "cmp", "stat",
    "file", "tree", "du", "df", "ps", "top", "uname", "hostname", "jq", "yq", "cut", "tr", "column", "basename",
    "dirname", "realpath", "readlink", "md5sum", "sha1sum", "sha256sum", "shasum", "cd", "true", "false", "test",
    "sleep", "nproc", "free", "uptime", "history", "man", "help", "tldr", "lsof", "netstat", "ss", "ping", "nslookup",
    "dig", "host", "traceroute", "get-childitem", "get-content", "select-string", "test-path", "get-location",
    "get-item", "get-process", "get-command", "resolve-path", "measure-object", "format-table", "format-list",
    "select-object", "where-object", "write-output", "write-host", "out-string", "get-date", "get-help", "nl", "od",
    "xxd", "hexdump", "strings", "zcat", "awk",
}
TEST_RUNNERS = {"pytest", "jest", "vitest", "mocha", "ava", "tap", "rspec", "phpunit", "ctest", "tox", "nox", "mypy", "pyright", "pylint", "flake8", "tsc", "hadolint", "shellcheck", "eslint", "ruff", "prettier", "stylelint", "golangci-lint", "black", "isort"}
FIX_FLAGS = {"--fix", "--write", "-w", "--apply", "--in-place", "-i"}
READ_SCRIPTS = re.compile(r"^(test|tests|lint|typecheck|type-check|check|tsc|verify|format:check|lint:check|audit)(:.*)?$")
DANGER_SCRIPTS = re.compile(r"deploy|release|publish|migrat|prod|seed|drop|reset|destroy|ship|upload", re.I)


def wrap(prefix_tokens, inner_tokens):
    return inner_tokens


def classify_tokens(tk, seg, r: R, depth):
    # strip wrappers that don't change what runs
    while tk:
        head = tk[0].lower()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tk[0]):
            if PROD_WORD.search(tk[0]):
                r.add(3, 1, f"runs with a production setting ({tk[0]})", "Check which environment this targets; prefer staging first.")
            tk = tk[1:]
        elif head in ("sudo", "doas"):
            r.add(3, 1, "runs with administrator privileges")
            tk = tk[1:]
            while tk and tk[0].startswith("-"):
                tk = tk[2:] if tk[0] in ("-u", "-g") else tk[1:]
        elif head in ("time", "nohup", "nice", "exec", "command", "builtin", "env") and len(tk) > 1:
            tk = tk[1:]
            while tk and tk[0].startswith("-"):
                tk = tk[1:]
        elif head == "xargs" and len(tk) > 1:
            tk = [t for t in tk[1:] if not t.startswith("-")]
        else:
            break
    if not tk:
        return
    name = os.path.basename(tk[0]).lower()
    name = re.sub(r"\.(exe|cmd|bat|ps1)$", "", name)
    args = tk[1:]
    low = [a.lower() for a in args]

    # shells and interpreters running inline code
    if name in ("bash", "sh", "zsh", "dash", "fish", "pwsh", "powershell", "cmd") and any(a.lower() in ("-c", "-command", "/c", "/k") for a in args):
        idx = next(i for i, a in enumerate(args) if a.lower() in ("-c", "-command", "/c", "/k"))
        inner = " ".join(args[idx + 1 :])
        r.merge(classify(inner, depth + 1, as_result=True))
        return
    if name in ("bash", "sh", "zsh", "pwsh", "powershell") and args and not args[0].startswith("-"):
        r.add(2, 2, f"runs the script {args[0]} (effects depend on its contents; read it first)")
        return

    if args and low[0] in ("--version", "-v", "-V", "version", "--help", "-h", "help") and len(args) == 1:
        r.add(1, 3, f"{name} {args[0]} only prints information")
        return

    if name in READ_ONLY:
        if name == "find" or (name == "awk" and "-i" in low):
            pass
        else:
            r.add(1, 3, f"{name} only reads")
            return
    if name == "find":
        if any(a in ("-delete", "-exec", "-execdir", "-ok") for a in low):
            if "-delete" in low or any(a in ("rm", "/bin/rm") for a in low):
                r.add(3, 0, "find deletes every matching file (bulk, unrecoverable for untracked files)", "Run the same find without -delete first and review the list.")
            else:
                r.add(2, 2, "find runs a command on every matching file")
        else:
            r.add(1, 3, "find only lists files")
        return
    if name == "sed":
        if any(a.startswith("-i") or a == "--in-place" for a in args):
            r.add(2, 3, "sed edits files in place (undo with git checkout / restore)")
        else:
            r.add(1, 3, "sed without -i only prints")
        return

    if name == "git":
        return git_rules(args, low, r)
    if name == "rm" or name in ("remove-item", "ri", "del", "erase", "rmdir", "rd"):
        return rm_rules(name, args, low, r)
    if name in ("mv", "cp", "mkdir", "touch", "ln", "tee", "patch", "chmod", "chown", "install", "rsync", "unzip", "tar", "move-item", "copy-item", "new-item", "set-content", "add-content", "out-file", "rename-item", "expand-archive"):
        if name == "rsync" and "--delete" in low:
            r.add(3, 1, "rsync --delete removes files at the destination", "Run with --dry-run first.")
        elif name == "rsync" and any(":" in a and not re.match(r"^[A-Za-z]:", a) for a in args):
            r.add(3, 1, "rsync to a remote host changes another machine")
        else:
            r.add(2, 3, f"{name} changes local files (recoverable with git or by reversing it)")
        return
    if name in ("kill", "pkill", "killall", "stop-process", "taskkill"):
        r.add(2, 2, "stops running processes")
        return
    if name in ("shutdown", "reboot", "halt", "poweroff", "restart-computer", "stop-computer", "systemctl", "service", "launchctl", "crontab", "sc"):
        if name == "systemctl" and low and low[0] in ("status", "list-units", "is-active", "cat", "show"):
            r.add(1, 3, "systemctl status only reads")
        elif name == "crontab" and low == ["-l"]:
            r.add(1, 3, "crontab -l only reads")
        else:
            r.add(3, 1, f"{name} changes system services or power state")
        return
    if name in ("npm", "pnpm", "yarn", "bun"):
        return js_pm_rules(name, args, low, r)
    if name in ("npx", "pnpx", "bunx"):
        inner = [a for a in args if a not in ("-y", "--yes", "--no-install", "-p")]
        if not inner:
            r.add(2, 2, "npx with no command")
            return
        return classify_tokens(inner, seg, r, depth)
    if name in ("python", "python3", "py", "node", "deno", "ruby", "perl", "php"):
        if len(low) >= 2 and low[0] == "-m":
            mod = low[1]
            if mod in ("pytest", "unittest", "mypy", "pyright", "pylint", "flake8", "doctest", "ruff", "black", "isort", "pip"):
                if mod == "pip":
                    return classify_tokens(["pip", *args[2:]], seg, r, depth)
                if mod in ("ruff", "black", "isort") and not any(a in FIX_FLAGS or a == "--check" for a in low):
                    r.add(2, 3, f"python -m {mod} rewrites files")
                    return
                r.add(1, 3, f"python -m {mod} runs checks")
                return
            if mod in ("http.server", "json.tool", "site", "venv"):
                r.add(2 if mod == "venv" else 1, 3, f"python -m {mod}")
                return
        if name == "node" and "--test" in low:
            r.add(1, 3, "node --test runs tests")
            return
        if any(a in ("-c", "-e", "--eval") for a in low):
            r.add(2, 2, f"{name} runs inline code (effects depend on the code; read it)")
            return
        r.add(2, 2, f"{name} runs a program whose effects depend on its code")
        return
    if name in TEST_RUNNERS:
        if any(a in FIX_FLAGS for a in low) and name in ("eslint", "ruff", "prettier", "stylelint", "golangci-lint", "black", "isort"):
            r.add(2, 3, f"{name} rewrites files to apply fixes")
        elif name in ("black", "isort", "prettier") and "--check" not in low:
            r.add(2, 3, f"{name} reformats files")
        elif name == "tsc" and "--noemit" not in low:
            r.add(2, 3, "tsc writes compiled output")
        else:
            r.add(1, 3, f"{name} runs tests or checks without changing code")
        return
    if name in ("cargo", "go", "dotnet", "mvn", "gradle", "gradlew", "./gradlew", "swift", "mix", "stack", "cabal", "make", "just", "bazel"):
        return build_rules(name, args, low, r)
    if name in ("pip", "pip3", "pipx", "poetry", "uv", "conda", "gem", "bundle", "composer", "brew", "apt", "apt-get", "dnf", "yum", "choco", "winget", "scoop", "twine"):
        return pkg_rules(name, args, low, r)
    if name in ("docker", "podman", "docker-compose"):
        return docker_rules(name, args, low, r)
    if name in ("terraform", "tofu", "pulumi", "kubectl", "helm", "ansible-playbook", "ansible", "aws", "gcloud", "az", "doctl", "eksctl", "kustomize"):
        return infra_rules(name, args, low, r)
    if name in ("vercel", "netlify", "fly", "flyctl", "heroku", "firebase", "serverless", "sls", "wrangler", "railway", "render", "amplify", "eb", "cf", "surge"):
        if low and low[0] in ("ls", "list", "logs", "status", "whoami", "info", "env", "inspect", "dev", "login"):
            r.add(1 if low[0] != "dev" else 2, 3, f"{name} {low[0]} does not deploy")
        else:
            r.add(3, 1, f"{name} deploys or changes a hosted service", "Note the current release/version so you can roll back (most platforms keep previous deployments).")
        return
    if name == "gh":
        return gh_rules(args, low, r)
    if name in ("curl", "wget", "http", "https", "xh", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"):
        return http_cli_rules(name, args, low, seg, r)
    if name in ("psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "mongo", "mongosh", "redis-cli", "cqlsh", "clickhouse-client"):
        return db_rules(name, args, r)
    if name in ("sendmail", "mail", "mailx", "mutt", "msmtp", "swaks"):
        r.add(3, 0, "sends email (cannot be unsent)")
        return
    if name == "stripe":
        if low and (low[-1] in ("list", "retrieve") or low[0] in ("listen", "logs", "login", "status")):
            r.add(1, 3, "stripe read-only command")
        else:
            r.add(3, 0, "Stripe payment API call (financial, may be irreversible)")
        return
    if name in ("ssh", "scp", "sftp"):
        r.add(3, 1, f"{name} acts on another machine")
        return
    if name in ("export", "set", "unset", "alias", "source", ".", "setx", "set-item", "set-variable"):
        r.add(2, 3, f"{name} changes the shell environment")
        return
    if name in ("open", "start", "xdg-open", "code", "explorer", "invoke-item"):
        r.add(1, 3, f"{name} opens a file or app for viewing")
        return
    r.add(2, 2, f"unknown command '{name}': treated as a mutation until you know what it does")


def git_rules(args, low, r: R):
    if not low:
        r.add(1, 3, "git with no subcommand")
        return
    while low and low[0] in ("-c", "-C", "--git-dir", "--work-tree"):
        low, args = low[2:], args[2:]
    if not low:
        return
    sub, rest = low[0], low[1:]
    ro = {"status", "log", "diff", "show", "blame", "rev-parse", "ls-files", "ls-remote", "describe", "shortlog", "grep", "fetch", "cat-file", "rev-list", "for-each-ref", "show-ref", "whatchanged", "count-objects", "check-ignore", "name-rev", "merge-base", "help", "version"}
    if sub in ro:
        r.add(1, 3, f"git {sub} only reads")
        return
    if sub == "push":
        force = any(a in ("-f", "--force", "--force-with-lease", "--force-if-includes") for a in rest) or any(a.startswith("+") or a.startswith("--force") for a in rest)
        if force:
            r.add(3, 0, "force-push rewrites history on the remote", "Before pushing, record the remote's current commit: git rev-parse <remote>/<branch>; it can be restored with a force-push of that SHA.")
        elif "--delete" in rest or "-d" in rest:
            r.add(3, 1, "deletes a branch on the remote", "Record the branch's SHA first so it can be re-pushed.")
        else:
            r.add(3, 1, "git push publishes commits to a shared remote (others may pull them)", "A pushed commit can be reverted with git revert, but not unpublished.")
        return
    if sub == "reset":
        if "--hard" in rest:
            r.add(3, 0, "git reset --hard discards uncommitted changes permanently", "Commit or stash first; note git rev-parse HEAD to return via the reflog.")
        else:
            r.add(2, 3, "git reset moves the branch pointer (recoverable via reflog)")
        return
    if sub == "clean":
        if any(a.startswith("-") and "f" in a for a in rest) and not any(a in ("-n", "--dry-run") for a in rest):
            r.add(3, 0, "git clean deletes untracked files permanently", "Run git clean -n first to see what would be deleted.")
        else:
            r.add(1, 3, "git clean dry run")
        return
    if sub == "branch":
        if "-D" in args[1:] or ("--delete" in rest and "--force" in rest):
            r.add(3, 1, "force-deletes a branch, possibly with unmerged work", "Record the branch SHA (git rev-parse <branch>) to recreate it.")
        elif any(a in ("-d", "--delete", "-m", "-M", "--move", "-c", "-C") for a in rest) or (rest and not rest[0].startswith("-")):
            r.add(2, 3, f"git branch {' '.join(args[1:])} changes local branches")
        else:
            r.add(1, 3, "git branch lists branches")
        return
    if sub in ("checkout", "restore"):
        discard = (sub == "checkout" and ("--" in rest or "." in rest)) or (sub == "restore" and "--staged" not in rest and rest)
        if discard:
            r.add(3, 0, f"git {sub} on paths discards uncommitted changes", "Stash or commit first if any of those changes matter.")
        else:
            r.add(2, 3, f"git {sub} switches branches or unstages files")
        return
    if sub == "stash":
        if rest and rest[0] in ("drop", "clear"):
            r.add(3, 0, "deletes stashed changes permanently")
        elif rest and rest[0] in ("list", "show"):
            r.add(1, 3, "lists or shows stashes")
        else:
            r.add(2, 3, "git stash saves and restores local changes")
        return
    if sub in ("filter-branch", "filter-repo", "replace"):
        r.add(3, 0, f"git {sub} rewrites history")
        return
    if sub in ("reflog", "gc", "prune", "update-ref") and any(a in ("expire", "--prune=now", "-d", "delete") for a in rest):
        r.add(3, 0, f"git {sub} permanently removes recovery points")
        return
    if sub == "tag":
        if rest and not rest[0].startswith("-") or any(a in ("-a", "-s", "-d", "-f") for a in rest):
            r.add(2, 3, "git tag creates or deletes a local tag")
        else:
            r.add(1, 3, "git tag lists tags")
        return
    if sub == "remote" and (not rest or rest[0] in ("-v", "show", "get-url")):
        r.add(1, 3, "git remote lists remotes")
        return
    if sub == "config" and any(a in ("--get", "--list", "-l", "--get-all") for a in rest):
        r.add(1, 3, "git config read")
        return
    r.add(2, 3, f"git {sub} changes the local repository (recoverable via reflog)")


def rm_rules(name, args, low, r: R):
    recursive = any((a.startswith("-") and not a.startswith("--") and "r" in a.lower()) or a in ("--recursive", "-recurse") for a in low)
    targets = [a for a in args if not a.startswith("-")]
    if name in ("rmdir", "rd") and not recursive:
        r.add(2, 3, "removes empty directories")
        return
    if not recursive:
        r.add(2, 2, f"deletes file(s) {' '.join(targets)[:80]} (recoverable only if tracked by git)", "Check git status: tracked files can be restored with git checkout.")
        return
    base = [os.path.basename(t.rstrip("/\\")) for t in targets]
    if targets and all(b in REGENERABLE for b in base):
        r.add(2, 3, f"deletes regenerable directories ({', '.join(base)})")
        return
    r.add(3, 0, f"recursively deletes {' '.join(targets)[:80] or 'directories'} (untracked contents are unrecoverable)", "Check git status for untracked files inside first, or move the folder aside instead of deleting it.")


def js_pm_rules(name, args, low, r: R):
    if not low:
        r.add(2, 3, f"{name} install")
        return
    sub = low[0]
    if sub in ("test", "t") or (name != "npm" and READ_SCRIPTS.match(sub)):
        r.add(1, 3, f"{name} {sub} runs checks")
        return
    if sub in ("publish", "unpublish", "deprecate", "dist-tag", "owner", "access"):
        r.add(3, 0 if sub == "unpublish" else 1, f"{name} {sub} changes the public package registry", "A published version number can never be reused, even after unpublishing.")
        return
    if sub in ("install", "i", "ci", "add", "remove", "rm", "uninstall", "update", "up", "upgrade", "link", "dedupe", "prune", "rebuild"):
        if "-g" in low or "--global" in low:
            r.add(2, 2, f"{name} {sub} changes globally installed packages")
        else:
            r.add(2, 3, f"{name} {sub} changes local dependencies (undo via the lockfile)")
        return
    if sub in ("ls", "list", "outdated", "view", "info", "why", "audit", "config", "whoami", "search", "explain", "doctor", "pack"):
        if sub == "audit" and "fix" in low:
            r.add(2, 3, f"{name} audit fix changes dependencies")
        else:
            r.add(1, 3, f"{name} {sub} only reads")
        return
    script = low[1] if sub in ("run", "run-script") and len(low) > 1 else sub
    if READ_SCRIPTS.match(script):
        r.add(1, 3, f"runs the '{script}' script (checks only)")
    elif DANGER_SCRIPTS.search(script):
        r.add(3, 1, f"runs the '{script}' script, whose name suggests deployment, release or data changes", "Read the script in package.json before approving.")
    else:
        r.add(2, 2, f"runs the '{script}' script (writes build output or starts a process)")


def build_rules(name, args, low, r: R):
    sub = low[0] if low else ""
    if sub in ("test", "check", "vet", "clippy", "fmt", "lint", "verify") and not any(a in FIX_FLAGS for a in low):
        if name == "cargo" and sub == "fmt" and "--check" not in low:
            r.add(2, 3, "cargo fmt rewrites files")
        elif name == "go" and sub == "fmt":
            r.add(2, 3, "go fmt rewrites files")
        else:
            r.add(1, 3, f"{name} {sub} runs checks")
        return
    if sub in ("publish", "deploy", "release", "upload", "push") or (name in ("make", "just") and any(DANGER_SCRIPTS.search(a) for a in low)):
        r.add(3, 1, f"{name} {' '.join(low[:2])} publishes or deploys")
        return
    if name in ("make", "just") and low and all(READ_SCRIPTS.match(a) for a in low if not a.startswith("-")):
        r.add(1, 3, f"{name} {' '.join(low)} runs checks")
        return
    r.add(2, 3, f"{name} {sub or ''} builds or runs code locally".replace("  ", " "))


def pkg_rules(name, args, low, r: R):
    sub = low[0] if low else ""
    if name == "twine" or sub in ("publish", "push", "upload"):
        r.add(3, 1, f"{name} {sub} publishes a package to a public registry")
        return
    if sub in ("list", "show", "freeze", "search", "info", "outdated", "check", "config", "env"):
        r.add(1, 3, f"{name} {sub} only reads")
        return
    if name in ("apt", "apt-get", "dnf", "yum", "brew", "choco", "winget", "scoop"):
        r.add(3, 2, f"{name} {sub} changes system-wide software")
        return
    r.add(2, 3, f"{name} {sub} changes project dependencies")


def docker_rules(name, args, low, r: R):
    sub = low[0] if low else ""
    if name == "docker" and sub == "compose":
        low = low[1:]
        sub = "compose-" + (low[0] if low else "")
    if sub in ("ps", "images", "logs", "inspect", "version", "info", "stats", "top", "history", "compose-ps", "compose-logs", "compose-config"):
        r.add(1, 3, f"docker {sub.replace('compose-', 'compose ')} only reads")
        return
    if sub in ("push", "login"):
        r.add(3, 1, "docker push publishes an image to a registry")
        return
    if sub in ("system", "volume", "image", "container", "network", "builder") and any(a in ("prune", "rm", "remove") for a in low[1:]):
        r.add(3, 0, f"docker {' '.join(low[:2])} permanently removes data or volumes", "List what will be removed first (docker volume ls / system df).")
        return
    if sub == "compose-down" and any(a in ("-v", "--volumes") for a in low):
        r.add(3, 0, "docker compose down -v deletes the project's volumes and their data")
        return
    r.add(2, 3, f"docker {sub.replace('compose-', 'compose ')} manages local containers")


def infra_rules(name, args, low, r: R):
    sub = low[0] if low else ""
    readonly = {"plan", "validate", "show", "output", "fmt", "version", "providers", "graph", "get", "describe", "logs", "top", "explain", "diff", "list", "ls", "status", "template", "lint", "preview", "config", "version", "whoami", "cluster-info", "api-resources", "auth", "search", "history"}
    if name in ("aws", "gcloud", "az", "doctl"):
        verbs = [a for a in low if not a.startswith("-")]
        if any(re.match(r"^(get|describe|list|ls|show|head|wait|lookup)(-|$)", v) for v in verbs[1:]) or verbs[:2] == ["s3", "ls"]:
            r.add(1, 3, f"{name} {' '.join(verbs[:2])} only reads")
        else:
            r.add(3, 1, f"{name} {' '.join(verbs[:3])} changes cloud resources", "Identify the account/project and region, and how to undo it, before approving.")
        return
    if sub in readonly and not (name in ("terraform", "tofu") and sub == "fmt" and "-check" not in low):
        r.add(1, 3, f"{name} {sub} only reads")
        return
    if name in ("terraform", "tofu") and sub in ("init", "fmt", "workspace"):
        r.add(2, 3, f"{name} {sub} changes local state only")
        return
    if sub in ("destroy", "delete", "uninstall", "drain"):
        r.add(3, 0, f"{name} {sub} removes infrastructure or workloads", "Make sure state and data are backed up and the target context/workspace is the intended one.")
        return
    r.add(3, 1, f"{name} {sub} changes live infrastructure", "Run the read-only form first (plan / diff / --dry-run) and check the target context.")


def gh_rules(args, low, r: R):
    noun = low[0] if low else ""
    verb = low[1] if len(low) > 1 else ""
    if noun == "api":
        method = "GET"
        for i, a in enumerate(low):
            if a in ("-x", "--method") and i + 1 < len(low):
                method = low[i + 1].upper()
        if method == "GET" and any(a in ("-f", "-F", "--field", "--raw-field", "--input") for a in low):
            method = "POST"
        r.merge(classify_http(method, "https://api.github.com/" + (args[1] if len(args) > 1 else ""), as_result=True))
        return
    if verb in ("view", "list", "status", "diff", "checks", "browse", "download", "watch") or noun in ("auth", "search", "status", "browse"):
        r.add(1, 3, f"gh {noun} {verb} only reads")
        return
    if noun == "repo" and verb == "clone":
        r.add(2, 3, "gh repo clone downloads a repository")
        return
    if verb in ("checkout", "co"):
        r.add(2, 3, "gh pr checkout switches the local branch")
        return
    rev = 0 if verb in ("delete", "merge") else 1
    r.add(3, rev, f"gh {noun} {verb} changes GitHub (visible to others)")


def http_cli_rules(name, args, low, seg, r: R):
    method = None
    url = next((a for a in args if re.match(r"^https?://", a, re.I)), "")
    for i, a in enumerate(args):
        al = a.lower()
        if al in ("-x", "--request", "-method") and i + 1 < len(args):
            method = args[i + 1].upper()
        elif al.startswith("-x") and len(a) > 2 and a[2:].isalpha():
            method = a[2:].upper()
        elif al in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-f", "--form", "--json", "-t", "--upload-file", "-body", "--post-data", "--post-file"):
            method = method or "POST"
    if name in ("http", "https", "xh") and args and args[0].upper() in ("POST", "PUT", "PATCH", "DELETE"):
        method = args[0].upper()
    r.merge(classify_http(method or "GET", url or "(unknown url)", as_result=True))
    if (method or "GET") == "GET" and any(a in ("-o", "--output", "-O", "--remote-name", "-outfile") for a in low) or (name == "wget" and "-O-" not in args and "-qO-" not in args and "-O" not in args and method is None):
        r.add(2, 3, f"{name} saves a download to disk")


def db_rules(name, args, r: R):
    sql = []
    for i, a in enumerate(args):
        if a in ("-c", "-e", "--command", "--execute", "--eval", "-q", "-Q") and i + 1 < len(args):
            sql.append(args[i + 1])
        elif not a.startswith("-") and re.search(r"\b(select|insert|update|delete|drop|create|alter|truncate)\b", a, re.I):
            sql.append(a)
    if name == "redis-cli":
        cmds = " ".join(a.lower() for a in args if not a.startswith("-"))
        if re.search(r"\b(flushall|flushdb)\b", cmds):
            r.add(3, 0, "redis FLUSHALL/FLUSHDB deletes all keys")
        elif re.search(r"\b(set|del|expire|hset|lpush|rpush|sadd|incr|decr|rename)\b", cmds):
            r.add(3, 1, "writes to Redis")
        else:
            r.add(1 if cmds else 3, 3 if cmds else 1, "redis read" if cmds else "interactive Redis session (any command can run)")
        return
    if not sql:
        r.add(3, 1, f"opens an interactive {name} session or runs a script file (any statement could run)", "Classify each statement before running it.")
        return
    for stmt in re.split(r";", " ; ".join(sql)):
        s = stmt.strip()
        if not s:
            continue
        verb = s.split()[0].upper()
        if verb in ("SELECT", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "WITH", "\\D", "\\DT", "\\L", "PRAGMA"):
            r.add(1, 3, f"SQL {verb} only reads")
        elif verb in ("INSERT", "CREATE"):
            r.add(2, 2, f"SQL {verb} adds data or objects")
        elif verb in ("DROP", "TRUNCATE"):
            r.add(3, 0, f"SQL {verb} permanently removes data", "Take a backup first (e.g. pg_dump -t <table> / mysqldump) and confirm the database name.")
        else:
            r.add(3, 1, f"SQL {verb} changes existing data or schema", "Run the matching SELECT first to see which rows are affected, and back up the table.")


# --------------------------------------------------------------- entry


def classify(command: str, depth: int = 0, as_result: bool = False):
    r = R()
    text = command.strip()
    if not text:
        r.add(1, 3, "empty command")
        return r if as_result else r.as_dict(command)
    hits = _forbidden(text)
    if hits:
        r.forbidden = True
        r.tier = 3
        r.rev = 0
        r.reasons.extend(f"FORBIDDEN: {h}" for h in hits)
        r.rollback.append("Do not run this. If the user truly needs it, they must run it themselves, outside the agent.")
        return r if as_result else r.as_dict(command)
    if depth < 4:
        for sub in substitutions(text):
            r.merge(classify(sub, depth + 1, as_result=True))
    for seg, piped in split_segments(text):
        tk = tokens(seg)
        if piped and tk and os.path.basename(tk[0]).lower() in ("sh", "bash", "zsh", "pwsh", "powershell", "python", "python3", "node", "iex", "invoke-expression"):
            r.add(3, 0, "pipes downloaded or generated text straight into an interpreter (runs unreviewed code)", "Download to a file, read it, then run it.")
            continue
        if has_write_redirect(seg):
            r.add(2, 3, "redirects output into a file (overwrites or appends)")
        for target in write_targets(seg, tk):
            why = sensitive_write(target)
            if why:
                r.add(3, 1, why, "Back up the file first (copy it aside) and show the user the exact change.")
        before = r.tier
        classify_tokens(tk, seg, r, depth)
        if r.tier >= 2 and PROD_WORD.search(seg) and r.tier < 3:
            r.add(3, 1, "mentions a production target", "Confirm the environment; prefer running against staging first.")
        _ = before
    if not r.reasons:
        r.add(1, 3, "no effect")
    return r if as_result else r.as_dict(command)


def classify_command(command: str) -> dict:
    return classify(command)


PAYMENT_HOSTS = re.compile(r"(^|\.)(stripe\.com|paypal\.com|braintreegateway\.com|adyen\.com|squareup\.com|checkout\.com|razorpay\.com|paystack\.co|flutterwave\.com|wise\.com|plaid\.com|klarna\.com|mollie\.com|coinbase\.com)$", re.I)
MESSAGE_HOSTS = re.compile(r"(^|\.)(twilio\.com|sendgrid\.com|mailgun\.net|postmarkapp\.com|resend\.com|slack\.com|discord\.com|twitter\.com|x\.com|graph\.facebook\.com|api\.linkedin\.com|mastodon\.social|api\.telegram\.org)$", re.I)


def classify_http(method: str, url: str, as_result: bool = False):
    r = R()
    m = (method or "GET").upper()
    host = re.sub(r"^[a-z]+://", "", url or "", flags=re.I).split("/")[0].split("@")[-1].split(":")[0].lower()
    local = host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]") or host.endswith(".local") or host.endswith(".localhost")
    if m in ("GET", "HEAD", "OPTIONS"):
        r.add(1, 3, f"HTTP {m} only reads")
    elif local:
        r.add(2, 2, f"HTTP {m} to a local development server")
    elif PAYMENT_HOSTS.search(host):
        r.add(3, 0, f"HTTP {m} to a payment provider ({host}): financial and possibly irreversible", "Use test-mode keys, and an idempotency key so a retry cannot charge twice.")
    elif MESSAGE_HOSTS.search(host):
        r.add(3, 0, f"HTTP {m} to a messaging or social service ({host}): sends something others will see")
    else:
        r.add(3, 1, f"HTTP {m} to {host or 'an external service'} changes external state", "Check whether the API supports undo or idempotency keys before sending.")
    return r if as_result else r.as_dict(f"{m} {url}", kind="http")


# ------------------------------------------------------------- audit log


def log_dir(explicit: str | None = None) -> Path:
    if explicit:
        p = Path(explicit)
    else:
        try:
            top = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
        except OSError:
            top = ""
        p = Path(top or os.getcwd()) / LOG_DIR
        if top:
            _exclude_from_git(Path(top))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _exclude_from_git(top: Path):
    try:
        rel = subprocess.run(["git", "rev-parse", "--git-path", "info/exclude"], cwd=top, capture_output=True, text=True).stdout.strip()
    except OSError:
        return
    if not rel:
        return
    ex = Path(rel) if os.path.isabs(rel) else top / rel
    ex.parent.mkdir(parents=True, exist_ok=True)
    text = ex.read_text(encoding="utf-8") if ex.exists() else ""
    if f"{LOG_DIR}/" not in text.split():
        with ex.open("a", encoding="utf-8") as fh:
            fh.write(("" if not text or text.endswith("\n") else "\n") + f"{LOG_DIR}/\n")


def _session_id(d: Path) -> str:
    f = d / "session"
    if f.exists():
        return f.read_text(encoding="utf-8").strip()
    sid = _dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    f.write_text(sid, encoding="utf-8")
    return sid


def append_log(directory, record: dict) -> dict:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    row = {"ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"), "session": _session_id(d), **record}
    with (d / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def read_log(directory) -> list:
    f = Path(directory) / "audit.jsonl"
    rows = []
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows


def render_audit(rows: list) -> str:
    def cell(x):
        return str(x if x is not None else "").replace("|", "\\|").replace("\n", " ")[:160]

    by_tier = {t: sum(1 for r in rows if r.get("tier") == t) for t in (1, 2, 3)}
    blocked = sum(1 for r in rows if r.get("decision") in ("blocked", "denied"))
    out = [
        "# actionGuard audit",
        "",
        f"{len(rows)} action(s): Tier 1: {by_tier[1]}, Tier 2: {by_tier[2]}, Tier 3: {by_tier[3]}, blocked or denied: {blocked}",
        "",
        "| Time (UTC) | Tier | Decision | Action | Intent | Affects | Reversibility | Approval / note |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        tier = "FORBIDDEN" if r.get("forbidden") else f"Tier {r.get('tier', '?')}"
        note = r.get("approval") or r.get("note") or ""
        if r.get("exit_code") is not None:
            note = f"{note} (exit {r['exit_code']})".strip()
        out.append(
            f"| {cell(r.get('ts', '')[11:19])} | {tier} | {cell(r.get('decision'))} | `{cell(r.get('action'))}` | {cell(r.get('intent'))} | "
            f"{cell(r.get('affects'))} | {cell(r.get('reversibility'))} | {cell(note)} |"
        )
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------ CLI


def _print_result(res: dict, as_json: bool):
    if as_json:
        print(json.dumps(res, indent=2))
        return
    head = "FORBIDDEN: do not run" if res["forbidden"] else res["tier_name"]
    if res["requires_approval"]:
        head += ": requires explicit user approval"
    print(head)
    print(f"Reversibility: {res['reversibility']}/3")
    print("Why:")
    for x in res["reasons"]:
        print(f"  - {x}")
    if res["rollback"]:
        print("Rollback / safety:")
        for x in res["rollback"]:
            print(f"  - {x}")


def _unexpand(args):
    """Undo what the calling shell did to an unquoted command: bash expands ~ to the
    home path, and Git Bash on Windows rewrites / to its install folder."""
    root = None
    if os.environ.get("MSYSTEM"):
        try:
            root = subprocess.run(["cygpath", "-m", "/"], capture_output=True, text=True).stdout.strip().rstrip("/") or None
        except OSError:
            root = None
    homes = {HOME_DIR.rstrip("/\\"), HOME_DIR.replace("\\", "/").rstrip("/")}
    out = []
    for a in args:
        bare = a.rstrip("/\\")
        if root and (bare == root or a.startswith(root + "/")):
            a = "/" + a[len(root):].lstrip("/")
        elif bare in homes:
            a = "~"
        out.append(a)
    return out


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    command = None
    if "--" in argv:
        i = argv.index("--")
        argv, rest = argv[:i], argv[i + 1 :]
        if len(rest) > 1:
            print("guard: tip: pass the command as one quoted argument (classify -- 'rm -rf ~'); otherwise your shell expands ~, globs and variables first.", file=sys.stderr)
            rest = _unexpand(rest)
        command = " ".join(rest)
    p = argparse.ArgumentParser(prog="guard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify", help="classify a shell command (after --) or an HTTP request")
    c.add_argument("--json", action="store_true")
    c.add_argument("--http", nargs=2, metavar=("METHOD", "URL"))
    lg = sub.add_parser("log", help="append an entry to the audit log")
    lg.add_argument("--action", required=True)
    lg.add_argument("--tier", type=int, choices=[1, 2, 3], required=True)
    lg.add_argument("--decision", required=True, choices=["auto", "approved", "denied", "blocked", "skipped"])
    lg.add_argument("--kind", default="shell", choices=["shell", "file", "http", "browser", "db", "other"])
    lg.add_argument("--intent")
    lg.add_argument("--affects")
    lg.add_argument("--reversibility")
    lg.add_argument("--rollback")
    lg.add_argument("--approval", help="the user's approving words, quoted")
    lg.add_argument("--exit-code", type=int)
    lg.add_argument("--forbidden", action="store_true")
    lg.add_argument("--note")
    lg.add_argument("--dir")
    au = sub.add_parser("audit", help="print the audit log as a table")
    au.add_argument("--json", action="store_true")
    au.add_argument("--dir")
    a = p.parse_args(argv)

    if a.cmd == "classify":
        if a.http:
            res = classify_http(a.http[0], a.http[1])
        elif command:
            res = classify_command(command)
        else:
            p.error("give a command after --, or --http METHOD URL")
        _print_result(res, a.json)
        return 4 if res["forbidden"] else {1: 0, 2: 2, 3: 3}[res["tier"]]
    if a.cmd == "log":
        rec = {k: v for k, v in vars(a).items() if k not in ("cmd", "dir") and v not in (None, False)}
        row = append_log(log_dir(a.dir), rec)
        print(f"logged: {row['ts']} Tier {row['tier']} {row['decision']}: {row['action'][:80]}")
        return 0
    if a.cmd == "audit":
        rows = read_log(log_dir(a.dir))
        print(json.dumps(rows, indent=2) if a.json else render_audit(rows))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
