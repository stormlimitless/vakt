# Architecture

Vakt is a single Go process. It listens on HTTP (and optionally HTTPS) and routes every request by its `Host` header to one of three destinations: a protected site, the admin interface, or a 404.

## Request flow

1. Requests under `/vakt/static/` are served from embedded assets regardless of host.
2. If the host equals `admin_host`, the request goes to the admin handler.
3. Otherwise the host is looked up in the `sites` table. An unknown host gets a 404 page.
4. `/vakt/login` and `/vakt/logout` on a known host are handled by Vakt itself.
5. For anything else: if the client IP is in the site's allowlist, the request is proxied straight through. If a valid `vakt_session` cookie for this site is present, it is proxied through. Otherwise the visitor is redirected to `/vakt/login`.

A proxied request reaches the upstream with `X-Forwarded-*` set and an `X-Vakt-User` header naming who was let through (`pin`, `password`, `allowlist`, or a username). Any client-supplied `X-Vakt-User` is overwritten.

## Packages

| Package            | Responsibility |
|--------------------|----------------|
| `cmd/vakt`         | Flag/env parsing, wiring, starting the HTTP and HTTPS servers |
| `internal/config`  | Loading `vakt.yaml`, env overrides, validation, upserting configured sites |
| `internal/store`   | SQLite access (via `modernc.org/sqlite`, no CGO) and all queries |
| `internal/auth`    | argon2id hashing, brute-force lockout, TOTP, session tokens |
| `internal/proxy`   | Host routing, the auth middleware, and the reverse proxy |
| `internal/admin`   | The admin UI, first-run setup, CSRF |
| `internal/tlsconf` | TLS: off, Let's Encrypt (autocert), or a manual certificate |
| `internal/web`     | Embedded templates and static assets, the render helper, security headers |

## Data model

SQLite tables: `sites`, `users`, `site_users` (which users may reach which site), `sessions`, `attempts` (lockout counters keyed by site and IP), and `setup_tokens`. Session and setup tokens are stored as SHA-256 hashes; PINs and passwords as argon2id; TOTP secrets encrypted with AES-GCM using a key generated on first run at `<data>/secret.key`.

## Sessions and cookies

Site logins use the `vakt_session` cookie; the admin interface uses a separate `vakt_admin` cookie so that reaching a protected site never grants admin access and vice versa. Sessions live in SQLite, so a restart does not sign everyone out, and expired rows are purged periodically. Each login rotates the session token.

## A few deliberate choices

- **Lockout cannot be turned off.** PINs are short by design, so a per-site, per-IP lockout is what actually protects them.
- **TOTP enrolment is stateless.** When an admin starts enrolment, the new secret is stored immediately but prefixed with `pending:`; login treats a pending secret as "no TOTP" until the user proves possession of a code, at which point the prefix is stripped. This avoids holding half-finished enrolment state in memory.
- **Security headers apply to Vakt's own pages only.** The login and admin pages get a strict CSP, `X-Frame-Options: DENY`, and friends; proxied responses are passed through untouched so Vakt does not rewrite the protected site's own headers.
- **`vakt.yaml` wins on restart.** Anything set in the config file is re-applied to the store at every start, so a declarative deployment stays declarative.
