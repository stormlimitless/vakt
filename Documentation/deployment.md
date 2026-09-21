# Deployment

## With Docker Compose

```yaml
services:
  vakt:
    image: ghcr.io/stormlimitless/vakt:latest
    ports: ["80:80", "443:443"]
    volumes: ["./data:/data"]
    environment:
      VAKT_ADMIN_HOST: vakt.example.com
    restart: unless-stopped
```

`docker compose up -d`, then read the setup URL from `docker compose logs vakt` and open it within the hour to create the first admin.

## DNS

Point the admin host and every protected site's host at the server's address. Vakt routes purely on the `Host` header, so each protected site is just another name resolving to the same Vakt instance.

## TLS

Set the mode in `vakt.yaml` under `tls`:

- `off` — HTTP only (put Vakt behind another TLS terminator).
- `autocert` — Let's Encrypt certificates, obtained automatically. Requires `email` and that ports 80 and 443 are reachable from the internet. Certificates are cached under `<data>/certs`.
- `manual` — supply `cert_file` and `key_file`.

Autocert only requests certificates for the hosts known at startup — the admin host plus every site then in the store. After adding a site through the admin UI, restart Vakt so its host is included.

## Behind another proxy

If Vakt sits behind a load balancer or Cloudflare, list the proxy's networks in `trusted_proxies` (CIDRs). Vakt then trusts `X-Forwarded-For` from those sources to determine the real client IP for allowlists and lockout. Without this, `X-Forwarded-For` is ignored and the direct peer is used.

When that proxy also terminates TLS, Vakt runs with `tls.mode: off` but visitors still arrive over HTTPS. Set `secure_cookies: true` (or `VAKT_SECURE_COOKIES=true`) so session cookies keep the `Secure` attribute — otherwise it is derived from `tls.mode` and would be dropped.

## Config vs. the admin UI

Anything in `vakt.yaml` is re-applied to the store on every start. If you set a site's PIN in the config and later change it in the admin UI, the config value wins again after a restart. Use the config file for a fully declarative deployment, or the admin UI for day-to-day changes — but not both for the same field.

## Setup token

The first-run setup URL contains a single-use token that expires after one hour. If it expires or is used, restart Vakt (with no admin user yet) to get a fresh one.

## Backup

All state — the database, the encryption key, and cached certificates — lives under `/data`. Back up that directory; restoring it is the whole recovery.
