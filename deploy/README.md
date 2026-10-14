# Self-built production deployment

Main H (linux/arm64), https://artex.zheqikejiai.com. This is the real backend,
not the frontend Mock demo. LLM configuration remains empty until configured
by the operator in the UI; deployment never starts a scan.

## Release flow

Jenkins `artex-deploy`: checkout this repository, Buildx `hermes-central`,
Registry `127.0.0.1:15000/artex/app:<full-git-sha>`, then SSH `h-host` for
`pull` + `up --no-build`. Both PUBLISH and DEPLOY default to false; no automatic
production trigger. DEPLOY implies PUBLISH. The build runs focused Go tests.
The image revision label and `/api/health` identify the built source.
`dev-<sha>` intentionally disables upstream binary self-updates; update through CI.

Runtime root: `/mnt/ebs-data/services/artex`, separate from Git/Jenkins workspace.
Copy `production.env.example` to `.env`, set a random hex PostgreSQL password,
and chmod 600. State is under `state/`: PostgreSQL, workspace data, editable
skills, config.json, and jwt.key. Create data/home and skills owned by 10001:10001;
copy initial repository skills once. Generate jwt.key before first launch, set
0600 and owner 10001:10001. Create config.json containing `{}` with the same owner.
The JWT key lives outside the browsable data directory and is mounted read-only.
The application is non-root, has no Docker socket, and publishes only loopback
18500 (web/API) and 18501 (recording proxy). Its tool processes share the application
container and network: do not treat it as isolation between untrusted tenants.

Initialize the administrator over loopback `POST /api/auth/init` with a generated
password **before** enabling nginx/DNS. Store the password in a root-only secrets
file outside the workspace. Verify login, protected routes return 401 anonymously,
first-init cannot repeat, and tasks/assets/findings are empty. No mock seed data.
Then install `nginx.conf`, run `nginx -t`, reload, and create a proxied Cloudflare
A record. The reused certificate is a Cloudflare Origin certificate, not a public CA.
SSE buffering is disabled. Access logging is disabled to avoid JWT query leakage.

## Operations

```sh
cd /mnt/ebs-data/services/artex
docker compose --env-file .env --env-file image.env -f docker-compose.yml ps
bash releases/$(cat .runtime-revision)/deploy/backup.sh
```

Backups briefly stop the application for consistent SQLite/files, dump PostgreSQL
in custom format, and restart via EXIT trap. The DB container is not recreated.
Backups contain secrets and must remain root-only. A failed rollout is not silently
rolled back: examine logs and the recorded pre-deploy backup.

Rollback code: select a previously verified SHA and invoke that release's
`deploy/deploy.sh SHA 127.0.0.1:15000/artex/app:SHA`. Database schema migrations run
at startup; image rollback alone does not undo them. For state recovery, stop artex,
restore the selected `.env`, `image.env`, compose and state tar, and restore the
PostgreSQL dump using `pg_restore --clean --if-exists -U artex -d artex` inside the
postgres service. Never extract an unreviewed backup over running state. Restart
using the matching recorded image and verify login plus business data.

Build overrides use the official npm/Go/Playwright sources. Playwright MCP/CLI and
browser versions are pinned together. `.dockerignore` excludes live env files,
JWT keys, host config and state. Browser tests must run under UID 10001 as well.
