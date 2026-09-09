# Codex-LB model bridge

This repository contains a standalone, user-managed bridge for routing Codex
model traffic through an authenticated local endpoint and an SSH-forwarded
upstream. It does not include a provider, credentials, host keys, or a
machine-specific deployment.

The desktop client keeps its built-in `openai` provider and ChatGPT OAuth
session. The bridge accepts only loopback traffic, checks the current OAuth
token from the local authentication snapshot, replaces it with a provider
token obtained from the configured helper, and forwards only approved headers.
The SSH tunnel is host-key pinned and forwards a second loopback port to the
configured upstream port on the remote host.

## Request path

```text
Codex app-server
  -> 127.0.0.1:<bridge-port>/<generated-64-hex-path>/backend-api/codex
  -> exact local ChatGPT bearer check
  -> provider token helper and request-header allowlist
  -> 127.0.0.1:<tunnel-port>
  -> host-key-pinned SSH tunnel
  -> 127.0.0.1:<remote-port> on the configured SSH host
```

The bridge supports these explicit routes:

- `GET /models`
- `GET /responses` as a WebSocket upgrade
- `POST /responses`, including incremental SSE fallback
- `POST /responses/compact`
- `POST /alpha/search`, the JSON web-search RPC used by recent Codex clients

All other routes fail closed. Browser-originated requests are rejected. The
incoming bearer must match the current token in the owner-only authentication
snapshot; the provider-token helper is not run before that check. Redirects
and upstream authentication failures become a generic local `502` response.
WebSocket frames and SSE payloads remain opaque and are not logged.

The bridge accepts only an HTTP upstream on IPv4 loopback. Request and response
headers use explicit allowlists, so account, organization, project, cookie,
API-key, attestation, and forwarding headers are not relayed. Routing hints
are validated and bounded before the provider helper can run. Request and
response sizes, connection counts, and idle time are bounded as well.

## Install

The installer requires an existing ChatGPT-authenticated Codex configuration,
an executable Codex client, an executable provider-token helper, an Ed25519
SSH identity, and an Ed25519 host key already present in the user's
`known_hosts`. Set installation-specific values before running it:

```sh
export CODEX_LB_TOKEN_HELPER=/path/to/provider-token-helper
export CODEX_EXECUTABLE=/path/to/codex
export CODEX_LB_SSH_HOST=YOUR_IPV4_ADDRESS
export CODEX_LB_SSH_USER=YOUR_SSH_ACCOUNT
export CODEX_LB_REMOTE_PORT=YOUR_REMOTE_PORT
# Optional: defaults to codex-lb-ssh-key, CODEX-LB bridge port 12455,
# and tunnel port 12456.
export CODEX_LB_SSH_IDENTITY_NAME=codex-lb-ssh-key

node install.mjs --install
```

`CODEX_LB_SSH_HOST` must be an IPv4 address because the generated tunnel unit
uses an exact systemd IP allowlist. The installer renders the SSH tunnel unit
with the supplied host, account, identity name, local tunnel port, and remote
port; the checked-in unit is a template and intentionally contains no target.
The provider helper must print one provider token for the `token` operation
and support a successful `status` operation. The example configuration shows
the complete bridge schema without any secret value.

The installer writes owner-readable configuration, installs the bridge and
rendered user units, validates them with `systemd-analyze`, enables the tunnel
and bridge, and updates only the top-level Codex provider/base URL settings.
It creates a private backup before changing files. To restore a backup:

```sh
node rollback.mjs --backup /path/to/backup-directory
```

Restart the desktop client after installation or rollback, then validate the
configured client operations in the target environment. Keep the generated
configuration and backups outside this repository.

## Development

Run the complete local test suite with:

```sh
npm test
```

The tests use synthetic credentials, hosts, and upstreams only. They exercise
route allowlisting, credential replacement, header filtering, WebSocket and
SSE forwarding, bounded streams, unit rendering, installation, rollback, and
failure recovery.

## License

No license is granted by this repository. Do not copy, modify, or redistribute
these files unless you have independent permission from the applicable
rights holder.
