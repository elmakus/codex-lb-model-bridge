# Codex-LB model bridge

This repository contains a standalone, user-managed bridge for routing Codex
traffic through an authenticated local endpoint and an SSH-forwarded upstream.
It does not include a provider, credentials, host keys, or a machine-specific
deployment.

The desktop client keeps its built-in `openai` provider and ChatGPT OAuth
session. The bridge accepts only loopback traffic, checks the current OAuth
token from the local authentication snapshot, replaces that bearer with a
provider token obtained from the configured helper, and then proxies the Codex
backend namespace as transparently as possible. The SSH tunnel is host-key
pinned and forwards a second loopback port to the configured upstream port on
the remote host.

## Request path

```text
Codex app-server
  -> 127.0.0.1:<bridge-port>/<generated-64-hex-path>/backend-api/codex[/...]
  -> exact local ChatGPT bearer check
  -> provider token helper
  -> transparent Codex HTTP / WebSocket proxying
  -> 127.0.0.1:<tunnel-port>/backend-api/codex[/...]
  -> host-key-pinned SSH tunnel
  -> 127.0.0.1:<remote-port> on the configured SSH host
```

The bridge deliberately does **not** maintain a feature allowlist such as
`/models`, `/responses`, `/alpha/search`, image, memory, or realtime routes.
Any HTTP route and method that remains inside the configured
`/backend-api/codex` namespace is forwarded. WebSocket upgrades are likewise
accepted for any path inside that namespace after validating the WebSocket
transport handshake.

This is intentional: the bridge is an authentication and transport adapter,
not an application firewall for individual Codex features. A new Codex route
or metadata header should not require a bridge release merely to keep the
desktop client working.

The security boundary remains narrow:

- the listener and upstream must both be IPv4 loopback;
- the public path contains a generated 64-hex component;
- the incoming bearer must exactly match the current ChatGPT OAuth snapshot;
- that ChatGPT bearer is never forwarded upstream;
- the upstream `Authorization` and `x-openai-actor-authorization` values are
  always set by the bridge;
- the destination is pinned to the configured loopback
  `/backend-api/codex` namespace, so the bridge is not an open proxy;
- HTTP hop-by-hop headers, plus headers named by `Connection`, are stripped and
  rebuilt as required by the next hop;
- proxy-identity metadata supplied by the desktop client (`Forwarded`,
  `X-Forwarded-*`, `X-Real-IP`, `True-Client-IP`, and `CF-Connecting-IP`) is
  stripped instead of being trusted by the loopback Codex-LB hop;
- request/response sizes, connection counts, helper runtime, connect time and
  idle time remain bounded;
- provider-side `401` responses become a generic local `502`, so a provider
  credential failure does not invalidate the desktop client's own ChatGPT
  login; application statuses such as `403` remain transparent;
- WebSocket frames and streamed response bodies remain opaque and are not
  logged;
- request logs redact arbitrary/dynamic path identifiers instead of recording
  them verbatim.

All other end-to-end request and response headers are preserved, including
future `x-codex-*` / `x-openai-*` metadata, cookies, `Set-Cookie`, and headers
that the current bridge version does not know by name. Request bodies are also
treated opaquely; the bridge does not require JSON or a fixed content encoding.

`Location` is normally preserved as application data. For an actual HTTP 3xx
redirect that points back into the same configured Codex upstream namespace,
the bridge rewrites only the local path prefix so a redirect-following client
returns through the generated bridge path instead of bypassing it. A non-3xx
`Location` value, including the value used to carry realtime call identity,
is not rewritten.

## Realtime note

Namespace transparency does not by itself guarantee every realtime transport
uses the bridge. Current Codex WebRTC sideband code can construct a direct
`api.openai.com` WebSocket URL independently of the configured provider base
URL. In a multi-account Codex-LB deployment, that creates an account-affinity
constraint that cannot be solved merely by accepting more bridge paths. The
bridge therefore remains transparent for any realtime HTTP/WebSocket traffic
that reaches it, but does not claim that provider-base rewriting alone routes
every WebRTC sideband through Codex-LB.

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
# Optional: defaults to codex-lb-ssh-key, bridge port 12455,
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

The tests use synthetic credentials, hosts, and upstreams only. Bridge tests
cover transparent forwarding of unknown/future HTTP routes, methods, body
types and application headers; proxy-identity stripping; current Codex routes;
credential replacement and rotation; namespace isolation; helper cancellation;
request/response limits and capacity release; SSE cancellation; redirect
rewriting; provider `401` masking versus `403` passthrough; dynamic-path log
redaction; and generic WebSocket paths and timeout cleanup. Installer and
rollback tests cover deployment and recovery.

## License

No license is granted by this repository. Do not copy, modify, or redistribute
these files unless you have independent permission from the applicable
rights holder.
