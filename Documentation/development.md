# Development

## Prerequisites

- Go 1.23 or newer
- The [Tailwind standalone CLI](https://github.com/tailwindlabs/tailwindcss/releases), only if you change the templates and need to rebuild the stylesheet

## Building and testing

```sh
go build ./cmd/vakt
go test ./...
```

The compiled stylesheet `internal/web/static/app.css` is committed, so `go build` and `go test` work without Node or Tailwind. After editing any template, regenerate it:

```sh
make css   # runs the Tailwind CLI over the templates
```

## Running locally

Create a config and a dummy upstream, then start Vakt:

```yaml
# data/vakt.yaml
admin_host: localhost
listen_http: ":8080"
sites:
  - host: app.localhost
    upstream: http://127.0.0.1:8081
    methods: [pin]
    pin: "1234"
```

```sh
# a throwaway upstream on :8081, then:
go run ./cmd/vakt -config data/vakt.yaml
```

Modern browsers resolve any `*.localhost` name to the loopback address, so `http://app.localhost:8080` reaches Vakt without editing your hosts file. The log prints a one-time setup URL for creating the first admin; open it, then sign in to the site at `app.localhost` with the PIN. The `data/` directory is gitignored.

## Conventions

- Run `gofmt -l .` and `go vet ./...` before committing; both must be clean.
- Comments explain a non-obvious decision, not what the code already says.
- Tests use the `_test` package and drive handlers through `httptest` rather than reaching into internals.
