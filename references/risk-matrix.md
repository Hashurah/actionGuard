# Risk classification matrix

How actionGuard sorts actions. `scripts/guard.py` implements most of the shell rows; the rest need your judgment. When a case is unclear, choose the higher tier.

## Contents

- [Reversibility scale](#reversibility-scale)
- [Escalation modifiers](#escalation-modifiers)
- [Shell and filesystem](#shell-and-filesystem)
- [Git](#git)
- [Packages, builds and scripts](#packages-builds-and-scripts)
- [Containers](#containers)
- [Databases](#databases)
- [Cloud, infrastructure and deployment](#cloud-infrastructure-and-deployment)
- [Network and APIs](#network-and-apis)
- [Browser actions](#browser-actions)
- [Communication and payments](#communication-and-payments)
- [System administration](#system-administration)
- [Forbidden list](#forbidden-list)

## Reversibility scale

| Score | Meaning | Examples |
|---|---|---|
| 3 | Nothing to undo, or undone trivially and fully | reads, tests, `git commit`, editing tracked files |
| 2 | Undoable with some effort or local knowledge | deleting untracked files you can regenerate, global installs, inline scripts |
| 1 | Partly undoable; others may already have seen or used it | `git push`, deploys, cloud changes, `UPDATE ... WHERE` |
| 0 | Cannot be undone | force-push, `git reset --hard` over uncommitted work, `DROP`, sent emails, payments |

## Escalation modifiers

Apply these on top of the base tier:

| Modifier | Effect |
|---|---|
| Target is production (`prod`, `production`, live URL, production profile, kube context or workspace) | Any mutation becomes Tier 3 |
| `sudo`, `doas`, administrator shell | Tier 3 |
| Path outside the project, or in the home directory, shell profile or system directories | Writes become Tier 3 |
| Credentials or secrets (`.env`, keys, tokens, `~/.ssh`, cloud credentials) | Writes become Tier 3; never print or send their contents |
| Wildcards or bulk deletes (`*`, `-delete`, `xargs rm`, many rows) | At least Tier 3 unless the scope is a regenerable folder |
| Output piped into a shell or interpreter (`curl ... | bash`) | Tier 3: unreviewed code |
| Unknown command or script | At least Tier 2; Tier 3 if it can reach the network or other machines |
| Compound command | The riskiest part decides |

## Shell and filesystem

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find` (listing), `pwd`, `stat`, `du`, `tree`, `jq`, `diff`, `echo` | `mkdir`, `touch`, `cp`, `mv`, `sed -i`, `tee`, writing files with `>` inside the project, `rm` of single files, `rm -rf` of regenerable folders (`node_modules`, `dist`, `build`, `target`, caches) | `rm -rf` of source or unknown folders, `find -delete`, `rsync --delete`, writing outside the project, `chmod`/`chown -R` on shared paths |

## Git

| Tier 1 | Tier 2 | Tier 3 | Forbidden |
|---|---|---|---|
| `status`, `log`, `diff`, `show`, `blame`, `fetch`, `branch` (list), `remote -v`, `stash list` | `add`, `commit`, `checkout -b`, `switch`, `stash`, `merge`, `rebase` (local), `cherry-pick`, `revert`, `tag`, `branch -d`, `reset` (soft or mixed), `pull` | `push`, `push --force` (non-protected branch), `reset --hard`, `clean -f`, `branch -D`, `checkout -- .`/`restore .`, `stash drop`/`clear`, `filter-repo`, deleting remote branches | force-push to, `+refspec` to, or deletion of `main`, `master`, `production`, `prod`, `release`, `live`, `trunk` |

## Packages, builds and scripts

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| `npm test`, `npm run lint/typecheck/check`, `pytest`, `cargo test/check/clippy`, `go test/vet`, `tsc --noEmit`, `npm ls`, `pip list` | `npm install/ci/add/remove`, `pip install` (in a venv), `cargo build`, `go build`, `npm run build/dev`, `make` (non-deploy targets), formatters with `--write`/`--fix` | `npm publish`, `cargo publish`, `twine upload`, `gem push`, scripts named deploy/release/publish/migrate/seed/prod, system package managers (`apt`, `brew`, `choco`, `winget`) |

## Containers

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| `docker ps/images/logs/inspect`, `docker compose ps/logs/config` | `docker build/run/exec/start/stop`, `docker compose up/down` | `docker push`, `docker volume rm`, `docker system/volume prune`, `docker compose down -v` |

## Databases

| Tier 1 | Tier 2 | Tier 3 | Forbidden |
|---|---|---|---|
| `SELECT`, `SHOW`, `EXPLAIN`, `DESCRIBE`, `\d` | `INSERT`, `CREATE` in a local or dev database | `UPDATE`/`DELETE` with `WHERE`, `ALTER`, `DROP TABLE`, `TRUNCATE`, `GRANT`/`REVOKE`, migrations, interactive sessions, Redis writes, `FLUSHALL` | `UPDATE`/`DELETE` without `WHERE`; `DROP DATABASE`/`SCHEMA` on production |

Before any Tier 3 statement, run the matching `SELECT` to see the affected rows, and take a backup (`pg_dump -t`, `mysqldump`, a copy of the SQLite file).

## Cloud, infrastructure and deployment

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| `terraform plan/validate/show`, `kubectl get/describe/logs/diff`, `helm list/template`, `aws ... describe/list/get`, `gcloud ... list/describe` | `terraform init`, `terraform fmt` | `terraform apply/destroy/import`, `kubectl apply/delete/scale/rollout`, `helm install/upgrade/uninstall`, `aws/gcloud/az` create/update/delete/deploy, `s3 rm/sync/cp`, `vercel`, `netlify deploy`, `fly deploy`, `firebase deploy`, `wrangler deploy` |

## Network and APIs

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| GET, HEAD, OPTIONS; `curl` without a body; `gh pr/issue view/list` | POST/PUT/PATCH/DELETE to `localhost` or a local dev server; downloading a file (`curl -o`) | POST/PUT/PATCH/DELETE to any external service; `gh pr create/merge`, `gh issue create/comment`, `gh release create`; webhooks |

## Browser actions

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| Navigating, reading, screenshots, filling a field without submitting | Changing settings of a local app under development | Submitting forms, logging in with real credentials, accepting terms, purchases, posting, sending messages, deleting anything, changing account or billing settings |

## Communication and payments

Always Tier 3, reversibility 0: sending email (`sendmail`, mail APIs), SMS, chat or social posts (Slack, Discord, X, LinkedIn), and any payment, refund, payout or transfer (Stripe, PayPal, Adyen, Square, bank APIs). Use test modes and sandbox keys where they exist, and idempotency keys for payment calls.

## System administration

| Tier 1 | Tier 2 | Tier 3 |
|---|---|---|
| `ps`, `systemctl status`, `crontab -l`, `df`, `free` | `kill` of your own processes, `export`/`set` in the session | `sudo`, `systemctl start/stop/restart`, `crontab -r`/edit, `shutdown`/`reboot`, `ssh`/`scp` to other machines, changing firewall or network settings |

## Forbidden list

These are refused regardless of context. If a user truly needs one, they run it themselves:

- `rm -r` of `/`, `/*`, `~`, `$HOME`, a drive root or a system directory (`/usr`, `/etc`, `/var`, `C:\`), with any combination of flags
- `Remove-Item -Recurse` of a drive root or the home directory
- `mkfs`, `Format-Volume`, `dd` or `>` to a raw disk device
- fork bombs
- `chmod`/`chown -R` on `/`
- `git push --force` (or `--force-with-lease`, or a `+refspec`) to a protected branch; `git push --delete` of a protected branch
- `DELETE FROM` or `UPDATE ... SET` without a `WHERE` clause
- `DROP DATABASE`/`DROP SCHEMA` on a production database
