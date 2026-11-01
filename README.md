# Vault Certificate Watcher

A small, read-only Go service for certificates stored in Vault PKI mounts. The UI has search, expiry status, a history filter, and certificate details. It needs no JavaScript build step or external font service.

The watcher discovers PKI mounts and refreshes every five minutes. Refresh now starts an immediate scan. A failed scan keeps the last complete result in memory and shows the error and last successful refresh time. Restarting the container clears this cache.

Green means more than 720 hours remain. Orange means 168 through 720 hours remain. Red means less than 168 hours remain. Expired and revoked certificates are hidden by default. Times use the viewer's local time zone. “Valid from” is the certificate's NotBefore time, which Vault can backdate.

## Run

Requirements: Docker with Compose, an existing Vault network, a trusted Vault CA, and a renewable read-only token.

1. Copy `.env.example` to `.env`. Set the host bind address, CA path, network, and private token and sink directories. Keep both directories outside this repository with mode `0700` and ownership matching `WATCHER_UID` and `WATCHER_GID`.
2. Put the seed token in `WATCHER_SECRET_DIR/token` with mode `0600`. Use a private credential flow. Never put a token in Compose, Git, or a command argument.
3. Set the address, TLS name, and CA path in `deploy/agent.hcl` for your Vault server. The Compose example uses the service name `vault` and verifies the TLS name `vault.home`. Set `VAULT_TLS_SERVER_NAME` to the same name for the watcher. For a custom Agent file, set `WATCHER_AGENT_CONFIG`.
4. Run `docker compose up -d --build`.
5. Open port 8201 on the configured host address. Run `docker compose logs agent watcher` to inspect failures.

The default host bind address is loopback. Binding a LAN address permits all devices that can reach that address to read the UI. This version uses HTTP and has no login. Restrict network access as needed for your installation.

The separate Vault Agent renews the seed token and writes `/sink/token`. The watcher mounts only the sink and public CA, both read-only. It never mounts an issuing Agent bundle or private key. Both services run without root privileges or Linux capabilities. The private sink directory must exist before startup.

For token replacement, write the new token to the private seed file and run `docker compose restart agent watcher`. If you replace the seed file by rename, the directory mount makes the replacement visible. The Agent cannot create a new token when the seed token expires or is revoked. The token_file method has this documented limit and is accepted for this first version.

Required token policy, repeated for each monitored PKI mount:

```hcl
path "sys/mounts" { capabilities = ["read"] }
path "pki/certs" { capabilities = ["list"] }
path "pki/certs/revoked" { capabilities = ["list"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
```

`sys/mounts` exposes mount names and metadata. Individual public certificates are read from Vault's unauthenticated certificate endpoint. The token needs no issue, revoke, or write permission. A PKI mount without list permission causes the scan to fail visibly rather than present an incomplete inventory.

The inventory includes only certificates Vault still stores. Certificates issued with storage disabled and records removed by tidy cannot appear. There is no history database and no alert delivery.

Sources: [Vault PKI API](https://developer.hashicorp.com/vault/api-docs/secret/pki), [Agent token_file method](https://developer.hashicorp.com/vault/docs/agent-and-proxy/autoauth/methods/token_file).

## Development

Run `go test -race ./...` and `go vet ./...`. Build with `go build .`. The server reads `VAULT_ADDR`, `VAULT_CACERT`, `VAULT_TLS_SERVER_NAME`, `VAULT_TOKEN_FILE`, and `LISTEN_ADDR`. Defaults match Compose. `/healthz` confirms the HTTP process is running; `/api/certificates` reports Vault scan health separately.

License: Apache-2.0.
