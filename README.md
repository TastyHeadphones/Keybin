# Keybin

Keybin is a minimal, passkey-only pasteboard focused on privacy and security. Accounts are created and recovered exclusively with WebAuthn passkeys—no emails or passwords.

## Features

- **WebAuthn only**: registration and sign-in exclusively via discoverable passkeys using [`@simplewebauthn`](https://simplewebauthn.dev/).
- **Secure defaults**: strict cookie policies, security headers, and origin enforcement.
- **Tiny stack**: Hono API, Drizzle ORM, React + Vite frontend.
- **Dual runtime**: runs on Cloudflare Workers (D1) or Node.js (SQLite) with the same code.
- **Automatic migrations**: database schema is created on first boot in both environments.

## Prerequisites

- Node.js 20+
- [pnpm](https://pnpm.io/) (Corepack works great)
- Passkey-capable browser (WebAuthn requires HTTPS or `localhost`)

## Environment variables

Copy `.env.example` to `.env` and adjust:

| Variable | Description |
| --- | --- |
| `ORIGIN` | Fully-qualified origin that serves the app (e.g. `https://keybin.example`). |
| `RP_ID` | WebAuthn relying party ID (domain only). |
| `RP_NAME` | Friendly relying party name displayed in the browser. |
| `SESSION_SECRET` | Long random secret used to sign session cookies. |
| `SQLITE_PATH` | Path for the SQLite database when running on Node/Docker. |
| `PORT` | Optional port override for Node development. |

For Cloudflare Workers you only need to set `ORIGIN`, `RP_ID`, `RP_NAME`, and `SESSION_SECRET` as secrets; `SQLITE_PATH` is ignored.

## Development

```bash
pnpm install
pnpm dev:node        # run against local SQLite (http://localhost:8080)
# or
pnpm dev:worker      # run with Miniflare
```

### Database tooling

```bash
pnpm db:generate  # update SQL migrations from the Drizzle schema
pnpm db:migrate   # apply migrations locally with drizzle-kit
```

## Production builds

```bash
pnpm build
```

The build outputs compiled server/worker bundles to `dist/` and the frontend to `dist/client`.

## Docker deployment

1. Populate `.env` with production values (the same file is read by Docker).
2. Build and start:

```bash
docker compose up -d
```

The container listens on port `8080` and persists SQLite data in the `keybin-data` volume.

## Cloudflare Workers deployment

1. (One-time) Create a D1 database and note the ID:
   ```bash
   npx wrangler d1 create keybin
   ```
2. Update `wrangler.toml` with the generated D1 `database_id`.
3. Configure secrets:
   ```bash
   npx wrangler secret put ORIGIN
   npx wrangler secret put RP_ID
   npx wrangler secret put RP_NAME
   npx wrangler secret put SESSION_SECRET
   ```
4. Deploy:
   ```bash
   npx wrangler deploy
   ```

The Worker build step runs `pnpm build`, which compiles the worker script and frontend assets and uploads the static bundle to Workers Sites. Database migrations run automatically on first request.

## Security notes

- All APIs enforce same-origin requests and disable CORS.
- Session cookies are signed, HttpOnly, Secure, and `SameSite=Strict`.
- Paste size is capped at 64 KB; expired pastes are garbage-collected automatically.
- Default CSP blocks third-party scripts, images, and styles.

## Troubleshooting

- Passkeys require a secure context. Browsers treat `http://localhost` as secure, but other hosts must use HTTPS.
- When running locally, ensure your browser allows `Secure` cookies for `localhost` or proxy through HTTPS if needed.
- If `pnpm install` fails because the registry is unreachable, configure an accessible npm registry mirror in `.npmrc` and retry.
