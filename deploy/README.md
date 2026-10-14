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

## Private SSO (required for production)

Production uses native oauth2_permission OIDC, not the standalone ARTEX password.
Register internal application `artex` (self-registration disabled), confidential
client `artex-web`, exact redirect `https://artex.zheqikejiai.com/auth/callback`,
scopes `openid profile`, authorization_code + refresh_token grants. Use platform
Argon2id secret hashing; set Access Token TTL 300 seconds and refresh TTL 8 hours.
Grant `artex:admin` only to explicitly authorized, active internal identities.
Any other SSO account is denied, including accounts registered for other apps.

Put the client secret in `secrets/artex-oidc-client-secret` (0600, UID 10001).
Set OIDC_SECRET_PATH and OIDC_CA_BUNDLE in .env. The trust bundle combines system
CAs and Cloudflare Origin CA; it must be readable by UID 10001 (0644). The container
pins the SSO hostname to host-gateway and verifies HTTPS, without disabling TLS.

The backend uses state + nonce + PKCE S256, verified ID Tokens for identity only,
and Access Token `/perm/me` responses for exact application + role authorization.
Opaque Secure/HttpOnly/SameSite=Lax cookies reference hashed session handles in
PostgreSQL; tokens are AES-GCM encrypted using a domain-separated key derived from
the persisted jwt.key. Sessions survive restarts and have an 8-hour maximum age.
Permissions are checked per request; role changes take effect after a fresh token
is issued/refreshed (up to the 5-minute Access Token TTL), not instantly from SQL.
Mutation requests require the exact ARTEX Origin. Logout invalidates the ARTEX
session; it does not log the user out of other SSO applications.

Local password login, initialization and password changes are disabled in OIDC
mode. Old ARTEX JWTs, query tokens and spoofed SSO headers cannot authorize access.
The entire UI/static/API surface is authenticated; health is loopback-only at
nginx. The minimal auth status, OIDC handshake and logged-out page remain public.
No scans/demo data are created during deployment or acceptance tests.

Only reopen nginx after targeted tests and loopback fail-closed checks pass.
Install nginx.conf, run nginx -t, then reload. DNS remains Cloudflare-proxied HTTPS;
"private" here means authorized internal accounts only, not a VPN-only network.
SSE buffering and cache are disabled; query/access logging is off to protect codes.

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

Never roll back a private instance to a pre-SSO image with the public ingress open.
First install a deny/maintenance ingress; then restore the selected version.

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
