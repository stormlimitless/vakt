# Vakt

Vakt is a self-hosted reverse proxy that puts a login in front of any website without touching the site itself. Point a domain at Vakt, tell it where the real site lives, and every visitor has to pass a PIN code, a shared password, or a named-user login (with an optional authenticator code) before the request is proxied through.

## Quick start

```yaml
# docker-compose.yml
services:
  vakt:
    image: ghcr.io/stormlimitless/vakt:latest
    ports: ["80:80", "443:443"]
    volumes: ["./data:/data"]
    environment:
      VAKT_ADMIN_HOST: vakt.example.com
    restart: unless-stopped
```

1. Point DNS for the admin host and every protected site at the server.
2. `docker compose up -d`
3. `docker compose logs vakt` prints a one-time setup URL. Open it within an hour to create the first admin user.
4. In the admin UI at `https://vakt.example.com/admin`, add a site: its host, where to proxy to, and which login methods to require.

A visitor to a protected host now sees a Vakt login page and reaches the site only after signing in.

## Configuration

Everything can be managed from the admin UI, or declared up front in `vakt.yaml` (see [`vakt.example.yaml`](vakt.example.yaml)):

```yaml
admin_host: vakt.example.com
tls:
  mode: autocert
  email: you@example.com
sites:
  - host: app.example.com
    upstream: http://app:3000
    methods: [pin]
    pin: "482913"
```

Sites listed in `vakt.yaml` are applied on every start; the admin UI edits the same store for everything else.

## What it does

- PIN code, shared password, or named users per site — in any combination
- Optional TOTP (authenticator app) for named users
- Per-site IP allowlist that skips the login
- Brute-force lockout per site and IP
- Automatic HTTPS via Let's Encrypt, or bring your own certificate
- One static binary, one SQLite file under `/data`, no external services

## Documentation

See [`Documentation/`](Documentation) for architecture, local development, and deployment.

## License

MIT
