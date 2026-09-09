import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createBridge, loadConfig, normalizeConfig } from "../bridge.mjs";

const CHATGPT_TOKEN = "chatgpt-test-token-that-must-never-reach-upstream";
const PROVIDER_TOKEN = "synthetic-provider-token-that-stays-local";
const PUBLIC_BASE = `/${"a".repeat(64)}/backend-api/codex`;
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

function writeProviderHelper(fixture, { providerToken = PROVIDER_TOKEN, delayMs = 0 } = {}) {
  fs.writeFileSync(fixture.helper, [
    "from pathlib import Path",
    "import time",
    `with Path(${JSON.stringify(fixture.marker)}).open("a", encoding="utf-8") as marker:`,
    "    marker.write(\"called\\n\")",
    `time.sleep(${JSON.stringify(delayMs / 1000)})`,
    `print(${JSON.stringify(providerToken)})`,
    "",
  ].join("\n"), { mode: 0o700 });
}

function helperCallCount(fixture) {
  if (!fs.existsSync(fixture.marker)) return 0;
  return fs.readFileSync(fixture.marker, "utf8").split("\n").filter(Boolean).length;
}

async function waitFor(predicate, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address()));
  });
}

function close(server) {
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(resolve));
}

function makeFixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "codex-lb-bridge-test-"));
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const authFile = path.join(directory, "auth.json");
  fs.writeFileSync(authFile, JSON.stringify({
    auth_mode: "chatgpt",
    tokens: { access_token: CHATGPT_TOKEN },
  }), { mode: 0o600 });
  const marker = path.join(directory, "helper-called");
  const helper = path.join(directory, "token-helper.py");
  const fixture = { authFile, directory, helper, marker };
  writeProviderHelper(fixture, { providerToken: options.providerToken || PROVIDER_TOKEN });
  return fixture;
}

function configFor(fixture, upstreamPort, overrides = {}) {
  return {
    version: 1,
    listenHost: "127.0.0.1",
    listenPort: 0,
    publicBasePath: PUBLIC_BASE,
    upstreamBaseUrl: `http://127.0.0.1:${upstreamPort}/backend-api/codex`,
    authFile: fixture.authFile,
    providerTokenHelper: fixture.helper,
    providerTokenPrefix: "synthetic-provider-",
    actorAuthorization: "codex-lb",
    tokenTimeoutMs: 2_000,
    connectTimeoutMs: 2_000,
    idleTimeoutMs: 5_000,
    maxConnections: 8,
    maxRequestBytes: 1024 * 1024,
    ...overrides,
  };
}

function request(url, options = {}, body = "") {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let firstChunkAt = null;
    const call = http.request(url, options, (response) => {
      const chunks = [];
      response.on("data", (chunk) => {
        if (firstChunkAt == null) firstChunkAt = Date.now();
        chunks.push(chunk);
      });
      response.on("end", () => resolve({
        body: Buffer.concat(chunks).toString("utf8"),
        firstChunkMs: firstChunkAt == null ? null : firstChunkAt - started,
        headers: response.headers,
        status: response.statusCode,
        totalMs: Date.now() - started,
      }));
    });
    call.once("error", reject);
    if (body) call.write(body);
    call.end();
  });
}

function requestThroughClose(url, options = {}, body = "") {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const call = http.request(url, options, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      const result = (completed) => finish({
        body: Buffer.concat(chunks),
        completed,
        headers: response.headers,
        status: response.statusCode,
      });
      response.once("end", () => result(true));
      response.once("aborted", () => result(false));
      response.once("error", () => result(false));
      response.once("close", () => result(response.complete));
    });
    call.once("error", (error) => finish({ error }));
    if (body) call.write(body);
    call.end();
  });
}

function authHeaders(extra = {}) {
  return { authorization: `Bearer ${CHATGPT_TOKEN}`, ...extra };
}

async function startBridge(t, config, logs = []) {
  const bridge = createBridge(config, { logger: (record) => logs.push(record) });
  const address = await bridge.listen();
  t.after(() => bridge.close());
  return { address, bridge, logs };
}

test("web RPC forwards search, open and non-search commands opaquely with the security boundary intact", async (t) => {
  const fixture = makeFixture(t);
  const received = [];
  const upstream = http.createServer((incoming, response) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
      received.push({ method: incoming.method, url: incoming.url, headers: incoming.headers, body: Buffer.concat(chunks).toString() });
      response.writeHead(200, { "content-type": "application/json", "set-cookie": "secret=1" });
      response.end('{"output":[],"opaque_future_field":true}');
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const base = `http://127.0.0.1:${address.port}${PUBLIC_BASE}`;
  const headers = authHeaders({ "content-type": "application/json", version: "0.153.4", "chatgpt-account-id": "private", cookie: "private=1" });
  const payload = JSON.stringify({ id: "synthetic", model: "gpt-test", input: [], commands: { search_query: [{ q: "OpenAI" }], open: [{ ref_id: "https://example.com" }], time: [{ utc_offset: "+00:00" }] }, settings: { allowed_callers: ["direct"], external_web_access: true }, max_output_tokens: 10000 });
  const result = await request(`${base}/alpha/search`, { method: "POST", headers }, payload);
  assert.equal(result.status, 200);
  assert.equal(result.body, '{"output":[],"opaque_future_field":true}');
  assert.equal(result.headers["set-cookie"], undefined);
  assert.equal(received[0].method, "POST");
  assert.equal(received[0].url, "/backend-api/codex/alpha/search");
  assert.equal(received[0].body, payload);
  assert.equal(received[0].headers.authorization, `Bearer ${PROVIDER_TOKEN}`);
  assert.equal(received[0].headers["x-openai-actor-authorization"], "codex-lb");
  assert.equal(received[0].headers.version, "0.153.4");
  assert.equal(received[0].headers["chatgpt-account-id"], undefined);
  assert.equal(received[0].headers.cookie, undefined);
  for (const [method, route] of [["GET", "/alpha/search"], ["POST", "/alpha/search/"], ["POST", "/alpha/other"], ["POST", "/search"]]) {
    assert.equal((await request(`${base}${route}`, { method, headers })).status, 404);
  }
  assert.equal((await request(`${base}/alpha/search`, { method: "POST", headers: { ...headers, authorization: "Bearer wrong" } }, payload)).status, 401);
  assert.equal((await request(`${base}/alpha/search`, { method: "POST", headers: { ...headers, origin: "https://example.com" } }, payload)).status, 403);
  assert.equal((await request(`${base}/alpha/search`, { method: "POST", headers: { ...headers, "content-type": "text/plain" } }, payload)).status, 415);
  assert.equal((await request(`${base}/alpha/search`, { method: "POST", headers: { ...headers, "content-length": String(2 * 1024 * 1024) } })).status, 413);
  assert.equal(received.length, 1);
  assert.equal(helperCallCount(fixture), 1);
});

test("configuration fails closed for non-loopback upstreams and unsafe config files", async (t) => {
  const fixture = makeFixture(t);
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, { upstreamBaseUrl: "http://198.51.100.10:18080/backend-api/codex" })),
    /upstream_must_be_http_ipv4_loopback/u,
  );
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, { publicBasePath: "/guessable/backend-api/codex" })),
    /invalid_public_base_path/u,
  );
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, { maxRequestBytes: 513 * 1024 * 1024 })),
    /stream_limit_too_high/u,
  );
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, { idleTimeoutMs: 25 * 60 * 60 * 1000 })),
    /idle_timeout_too_high/u,
  );

  const configPath = path.join(fixture.directory, "config.json");
  fs.writeFileSync(configPath, JSON.stringify(configFor(fixture, 18080)), { mode: 0o644 });
  assert.throws(() => loadConfig(configPath), /config_unsafe_mode/u);
  fs.chmodSync(configPath, 0o600);
  assert.equal(loadConfig(configPath).listenHost, "127.0.0.1");

  const symlink = path.join(fixture.directory, "config-link.json");
  fs.symlinkSync(configPath, symlink);
  assert.throws(() => loadConfig(symlink), /config_open_failed/u);
});

test("wrong auth and browser requests are rejected before provider-key lookup", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer((_req, response) => response.end("unexpected"));
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const base = `http://127.0.0.1:${address.port}${PUBLIC_BASE}`;

  const wrong = await request(`${base}/models`, { headers: { authorization: "Bearer wrong" } });
  assert.equal(wrong.status, 401);
  assert.equal(fs.existsSync(fixture.marker), false);

  const browser = await request(`${base}/models`, {
    headers: authHeaders({ origin: "https://hostile.example" }),
  });
  assert.equal(browser.status, 403);
  assert.equal(fs.existsSync(fixture.marker), false);

  const outside = await request(`http://127.0.0.1:${address.port}/backend-api/codex/models`, {
    headers: authHeaders(),
  });
  assert.equal(outside.status, 404);
  assert.equal(fs.existsSync(fixture.marker), false);
});

test("routing hints are strictly validated before provider-key lookup", async (t) => {
  const fixture = makeFixture(t);
  let upstreamCalls = 0;
  const upstream = http.createServer((_request, response) => {
    upstreamCalls += 1;
    response.end("unexpected");
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`;

  for (const routingHint of [
    "tier=priority",
    "model=gpt test",
    "model=gpt;tier=priority;extra=value",
    `model=${"a".repeat(507)}`,
  ]) {
    const result = await request(url, {
      headers: authHeaders({ "x-codex-routing-hint": routingHint }),
    });
    assert.equal(result.status, 400, routingHint);
  }

  const duplicate = await request(url, {
    headers: authHeaders({
      "x-codex-routing-hint": ["model=gpt-one", "model=gpt-two"],
    }),
  });
  assert.equal(duplicate.status, 400);
  assert.equal(helperCallCount(fixture), 0);
  assert.equal(upstreamCalls, 0);
});

test("an unreadable auth snapshot returns 503 instead of a false credential mismatch", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer((_request, response) => response.end("unexpected"));
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  fs.writeFileSync(fixture.authFile, "{", { mode: 0o600 });

  const result = await request(
    `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`,
    { headers: authHeaders() },
  );
  assert.equal(result.status, 503);
  assert.equal(helperCallCount(fixture), 0);
});

test("ChatGPT and provider credential rotations are observed on the next request", async (t) => {
  const fixture = makeFixture(t);
  const observed = [];
  const upstream = http.createServer((incoming, response) => {
    observed.push(incoming.headers.authorization);
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"data":[]}');
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`;

  const initial = await request(url, { headers: authHeaders() });
  assert.equal(initial.status, 200);

  const rotatedChatGptToken = "chatgpt-rotated-token-that-is-current-now";
  fs.writeFileSync(fixture.authFile, JSON.stringify({
    auth_mode: "chatgpt",
    tokens: { access_token: rotatedChatGptToken },
  }), { mode: 0o600 });
  const rotatedProviderToken = "synthetic-provider-rotated-token-that-is-current-now";
  writeProviderHelper(fixture, { providerToken: rotatedProviderToken });

  const rotated = await request(url, {
    headers: { authorization: `Bearer ${rotatedChatGptToken}` },
  });
  assert.equal(rotated.status, 200);
  const stale = await request(url, { headers: authHeaders() });
  assert.equal(stale.status, 401);
  assert.deepEqual(observed, [
    `Bearer ${PROVIDER_TOKEN}`,
    `Bearer ${rotatedProviderToken}`,
  ]);
  assert.equal(helperCallCount(fixture), 2);
});

test("disconnect during provider lookup cancels the helper and promptly frees capacity", async (t) => {
  const fixture = makeFixture(t);
  writeProviderHelper(fixture, { delayMs: 10_000 });
  const upstream = http.createServer((_incoming, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"data":[]}');
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
    tokenTimeoutMs: 5_000,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`;

  const abandoned = http.request(url, { headers: authHeaders() });
  abandoned.once("error", () => {});
  abandoned.end();
  await waitFor(() => helperCallCount(fixture) === 1);
  abandoned.destroy();
  writeProviderHelper(fixture);
  await new Promise((resolve) => setTimeout(resolve, 100));

  const started = Date.now();
  const next = await request(url, { headers: authHeaders() });
  assert.equal(next.status, 200);
  assert.ok(Date.now() - started < 1_000);
  assert.equal(helperCallCount(fixture), 2);
});

test("chunked request limit returns 413 without consuming a capacity slot", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer((incoming, response) => {
    incoming.resume();
    incoming.once("end", () => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true}');
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
    maxRequestBytes: 16,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/responses`;

  const oversized = await request(url, {
    method: "POST",
    headers: authHeaders({ "content-type": "application/json" }),
  }, "x".repeat(64));
  assert.equal(oversized.status, 413);
  const next = await request(url, {
    method: "POST",
    headers: authHeaders({ "content-type": "application/json" }),
  }, '{"ok":true}');
  assert.equal(next.status, 200);
});

test("response limit is exact and an oversized stream does not leak capacity", async (t) => {
  const fixture = makeFixture(t);
  let calls = 0;
  const upstream = http.createServer((_incoming, response) => {
    calls += 1;
    response.writeHead(200, { "content-type": "text/event-stream" });
    response.end(calls === 1 ? "x".repeat(64) : "ok");
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
    maxResponseBytes: 16,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`;

  const oversized = await requestThroughClose(url, { headers: authHeaders() });
  assert.equal(oversized.status, 200);
  assert.equal(oversized.completed, false);
  assert.ok(oversized.body.length <= 16);
  const next = await request(url, { headers: authHeaders() });
  assert.equal(next.status, 200);
  assert.equal(next.body, "ok");
});

test("cancelling an SSE consumer closes upstream and frees capacity", async (t) => {
  const fixture = makeFixture(t);
  let calls = 0;
  let firstClosed = false;
  const upstream = http.createServer((_incoming, response) => {
    calls += 1;
    if (calls === 1) {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("data: first\n\n");
      response.once("close", () => { firstClosed = true; });
      return;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"data":[]}');
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`;

  await new Promise((resolve, reject) => {
    const call = http.request(url, { headers: authHeaders() }, (response) => {
      response.once("data", () => response.destroy());
      response.once("close", resolve);
    });
    call.once("error", reject);
    call.end();
  });
  await waitFor(() => firstClosed);
  const next = await request(url, { headers: authHeaders() });
  assert.equal(next.status, 200);
});

test("HTTP forwarding replaces credentials, uses an allowlist, and streams SSE", async (t) => {
  const fixture = makeFixture(t);
  const received = [];
  const upstream = http.createServer((incoming, response) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
      received.push({
        body: Buffer.concat(chunks).toString("utf8"),
        headers: incoming.headers,
        method: incoming.method,
        url: incoming.url,
      });
      response.writeHead(200, {
        "cf-ray": "safe-cloudflare-request-id",
        "content-type": "text/event-stream",
        etag: '"safe-response-etag"',
        "openai-model": "gpt-upstream",
        "set-cookie": "must-not-return=1",
        "x-codex-active-limit": "codex-other",
        "x-codex-credits-balance": "42",
        "x-codex-credits-has-credits": "true",
        "x-codex-credits-unlimited": "false",
        "x-codex-other-limit-name": "Other Codex limit",
        "x-codex-other-primary-reset-at": "1700000000",
        "x-codex-other-primary-used-percent": "12",
        "x-codex-other-primary-window-minutes": "300",
        "x-codex-promo-message": "safe promo",
        "x-codex-rate-limit-reached-type": "primary",
        "x-codex-safety-buffering-enabled": "true",
        "x-codex-safety-buffering-faster-model": "gpt-fast",
        "x-codex-turn-state": "server-turn-state",
        "x-models-etag": "safe-models-etag",
        "x-oai-request-id": "safe-oai-request-id",
        "x-openai-model": "gpt-upstream-alias",
        "x-reasoning-included": "true",
        "x-request-id": "safe-request-id",
        "x-upstream-secret": "must-not-return",
      });
      response.write("data: first\n\n");
      setTimeout(() => response.end("data: second\n\n"), 120);
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const logs = [];
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port), logs);
  const payload = JSON.stringify({ model: "gpt-test", input: "hello" });
  const expectedForwarded = {
    "x-client-request-id": "safe-client-request-id",
    "x-codex-beta-features": "safe_beta",
    "x-codex-inference-call-id": "safe-inference-call-id",
    "x-codex-installation-id": "safe-installation-id",
    "x-codex-parent-thread-id": "safe-parent-thread-id",
    "x-codex-routing-hint": "model=gpt-test;tier=priority",
    "x-codex-turn-metadata": "safe-turn-metadata",
    "x-codex-turn-state": "client-turn-state",
    "x-codex-window-id": "safe-window-metadata",
    "x-openai-internal-codex-responses-lite": "true",
    "x-openai-subagent": "collab_spawn",
    "x-responsesapi-include-timing-metrics": "true",
  };
  const result = await request(`http://127.0.0.1:${address.port}${PUBLIC_BASE}/responses`, {
    method: "POST",
    headers: authHeaders({
      ...expectedForwarded,
      "chatgpt-account-id": "must-not-leave-loopback",
      cookie: "must-not-leave-loopback",
      "content-type": "application/json",
      "openai-account-id": "must-not-leave-loopback",
      "openai-organization": "must-not-leave-loopback",
      "openai-project": "must-not-leave-loopback",
      originator: "codex_cli_rs",
      "x-api-key": "must-not-leave-loopback",
      "x-codex-beta": "must-not-leave-loopback",
      "x-codex-subagent": "must-not-leave-loopback",
      "x-oai-attestation": "must-not-leave-loopback",
      "x-openai-fedramp": "must-not-leave-loopback",
      "x-unknown-new-header": "must-not-leave-loopback",
    }),
  }, payload);

  assert.equal(result.status, 200);
  assert.equal(result.body, "data: first\n\ndata: second\n\n");
  assert.ok(result.firstChunkMs < result.totalMs - 50, JSON.stringify(result));
  assert.equal(result.headers["set-cookie"], undefined);
  assert.equal(result.headers["x-upstream-secret"], undefined);
  assert.equal(result.headers["x-request-id"], "safe-request-id");
  for (const [name, value] of Object.entries({
    "cf-ray": "safe-cloudflare-request-id",
    etag: '"safe-response-etag"',
    "openai-model": "gpt-upstream",
    "x-codex-credits-balance": "42",
    "x-codex-other-limit-name": "Other Codex limit",
    "x-codex-other-primary-used-percent": "12",
    "x-codex-safety-buffering-enabled": "true",
    "x-codex-turn-state": "server-turn-state",
    "x-models-etag": "safe-models-etag",
    "x-oai-request-id": "safe-oai-request-id",
    "x-openai-model": "gpt-upstream-alias",
    "x-reasoning-included": "true",
  })) {
    assert.equal(result.headers[name], value);
  }
  assert.equal(received.length, 1);
  assert.equal(received[0].url, "/backend-api/codex/responses");
  assert.equal(received[0].body, payload);
  assert.equal(received[0].headers.authorization, `Bearer ${PROVIDER_TOKEN}`);
  assert.equal(received[0].headers["x-openai-actor-authorization"], "codex-lb");
  for (const [name, value] of Object.entries(expectedForwarded)) {
    assert.equal(received[0].headers[name], value);
  }
  for (const forbidden of [
    "chatgpt-account-id",
    "cookie",
    "openai-account-id",
    "openai-organization",
    "openai-project",
    "x-api-key",
    "x-codex-beta",
    "x-codex-subagent",
    "x-oai-attestation",
    "x-openai-fedramp",
    "x-unknown-new-header",
  ]) {
    assert.equal(received[0].headers[forbidden], undefined);
  }
  assert.doesNotMatch(JSON.stringify(received), new RegExp(CHATGPT_TOKEN, "u"));
  assert.doesNotMatch(JSON.stringify(logs), /chatgpt-test-token|synthetic-provider/u);
  assert.deepEqual(logs.at(-1), { event: "request_complete", route: "responses", status: 200 });
});

test("upstream redirects and provider authentication failures become generic 502 responses", async (t) => {
  const fixture = makeFixture(t);
  let status = 302;
  const upstream = http.createServer((_incoming, response) => {
    response.writeHead(status, { location: "http://credential-leak.invalid/collect", "www-authenticate": "Bearer secret" });
    response.end();
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models?client_version=test`;

  const redirect = await request(url, { headers: authHeaders() });
  assert.equal(redirect.status, 502);
  assert.equal(redirect.headers.location, undefined);
  assert.equal(redirect.headers["www-authenticate"], undefined);

  status = 401;
  const unauthorized = await request(url, { headers: authHeaders() });
  assert.equal(unauthorized.status, 502);
  assert.equal(unauthorized.headers["www-authenticate"], undefined);
});

function websocketHandshake(port, requestPath, authorization, options = {}) {
  return new Promise((resolve, reject) => {
    const key = options.key || crypto.randomBytes(16).toString("base64");
    const started = Date.now();
    const socket = net.createConnection({ host: "127.0.0.1", port });
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("websocket handshake timeout"));
    }, options.timeoutMs || 3_000);
    socket.once("error", reject);
    socket.once("connect", () => {
      const headers = [
        `GET ${requestPath} HTTP/1.1`,
        `Host: 127.0.0.1:${port}`,
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Key: ${key}`,
        `Authorization: ${authorization}`,
        "Originator: codex_cli_rs",
        "X-Codex-Beta: must-not-leave-loopback",
        "X-Codex-Beta-Features: safe_beta",
        `X-Codex-Routing-Hint: ${options.routingHint ?? "model=gpt-test;tier=priority"}`,
        "X-Codex-Subagent: must-not-leave-loopback",
        "X-Codex-Turn-State: client-turn-state",
        "X-Codex-Window-Id: safe-window",
        "X-OpenAI-Subagent: collab_spawn",
        "",
        "",
      ];
      socket.write(headers.join("\r\n"));
    });
    socket.on("data", function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      const marker = buffer.indexOf("\r\n\r\n");
      if (marker < 0) return;
      // Stop flowing before handing the socket to the caller. Otherwise the
      // first WebSocket frame can arrive after this listener is removed but
      // before the awaiting caller installs its own data listener.
      socket.pause();
      socket.removeListener("data", onData);
      clearTimeout(timer);
      resolve({
        headers: buffer.subarray(0, marker + 4).toString("latin1"),
        key,
        rest: buffer.subarray(marker + 4),
        socket,
        totalMs: Date.now() - started,
      });
    });
  });
}

test("WebSocket upgrade validates both auth domains and tunnels frames", async (t) => {
  const fixture = makeFixture(t);
  const upstreamObserved = {};
  const upstream = http.createServer();
  upstream.on("upgrade", (request, socket) => {
    upstreamObserved.authorization = request.headers.authorization;
    upstreamObserved.actor = request.headers["x-openai-actor-authorization"];
    upstreamObserved.chatgptAccount = request.headers["chatgpt-account-id"];
    upstreamObserved.codexBeta = request.headers["x-codex-beta"];
    upstreamObserved.codexBetaFeatures = request.headers["x-codex-beta-features"];
    upstreamObserved.codexSubagent = request.headers["x-codex-subagent"];
    upstreamObserved.openAiSubagent = request.headers["x-openai-subagent"];
    upstreamObserved.routingHint = request.headers["x-codex-routing-hint"];
    upstreamObserved.turnState = request.headers["x-codex-turn-state"];
    upstreamObserved.window = request.headers["x-codex-window-id"];
    const accept = crypto.createHash("sha1")
      .update(request.headers["sec-websocket-key"] + WS_GUID)
      .digest("base64");
    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Accept: ${accept}`,
      "OpenAI-Model: gpt-upstream-ws",
      "Set-Cookie: must-not-return=1",
      "X-Codex-Turn-State: server-turn-state-ws",
      "X-Reasoning-Included: true",
      "X-Upstream-Secret: must-not-return",
      "",
      "",
    ].join("\r\n"));
    socket.write(Buffer.from([0x81, 0x02, 0x4f, 0x4b]));
    socket.once("data", (chunk) => {
      upstreamObserved.clientFrame = Buffer.from(chunk);
      socket.end();
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const logs = [];
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port), logs);

  const connection = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/responses`,
    `Bearer ${CHATGPT_TOKEN}`,
  );
  assert.match(connection.headers, /^HTTP\/1\.1 101 /u);
  const expectedAccept = crypto.createHash("sha1").update(connection.key + WS_GUID).digest("base64");
  const acceptLine = connection.headers
    .split("\r\n")
    .find((line) => line.toLowerCase().startsWith("sec-websocket-accept:"));
  assert.equal(acceptLine?.slice(acceptLine.indexOf(":") + 1).trim(), expectedAccept);
  assert.match(connection.headers, /openai-model: gpt-upstream-ws/iu);
  assert.match(connection.headers, /x-codex-turn-state: server-turn-state-ws/iu);
  assert.match(connection.headers, /x-reasoning-included: true/iu);
  assert.doesNotMatch(connection.headers, /set-cookie|x-upstream-secret/iu);
  let serverFrame = connection.rest;
  if (serverFrame.length) {
    connection.socket.resume();
  } else {
    const nextData = new Promise((resolve) => connection.socket.once("data", resolve));
    connection.socket.resume();
    serverFrame = await nextData;
  }
  assert.deepEqual(Buffer.from(serverFrame), Buffer.from([0x81, 0x02, 0x4f, 0x4b]));
  const clientFrame = Buffer.from([0x81, 0x80, 0x00, 0x00, 0x00, 0x00]);
  connection.socket.write(clientFrame);
  await new Promise((resolve) => connection.socket.once("close", resolve));

  assert.equal(upstreamObserved.authorization, `Bearer ${PROVIDER_TOKEN}`);
  assert.equal(upstreamObserved.actor, "codex-lb");
  assert.equal(upstreamObserved.chatgptAccount, undefined);
  assert.equal(upstreamObserved.codexBeta, undefined);
  assert.equal(upstreamObserved.codexBetaFeatures, "safe_beta");
  assert.equal(upstreamObserved.codexSubagent, undefined);
  assert.equal(upstreamObserved.openAiSubagent, "collab_spawn");
  assert.equal(upstreamObserved.routingHint, "model=gpt-test;tier=priority");
  assert.equal(upstreamObserved.turnState, "client-turn-state");
  assert.equal(upstreamObserved.window, "safe-window");
  assert.deepEqual(upstreamObserved.clientFrame, clientFrame);
  assert.ok(logs.some((entry) => entry.event === "websocket_connected"));
  assert.doesNotMatch(JSON.stringify(logs), /chatgpt-test-token|synthetic-provider/u);
});

test("WebSocket rejects wrong client auth without invoking the provider helper", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer();
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const connection = await websocketHandshake(address.port, `${PUBLIC_BASE}/responses`, "Bearer wrong");
  assert.match(connection.headers, /^HTTP\/1\.1 401 /u);
  connection.socket.destroy();
  assert.equal(fs.existsSync(fixture.marker), false);
});

test("WebSocket rejects non-canonical keys before provider-key lookup", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer();
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const canonical = crypto.randomBytes(16).toString("base64");
  const connection = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/responses`,
    `Bearer ${CHATGPT_TOKEN}`,
    { key: `${canonical}!` },
  );
  assert.match(connection.headers, /^HTTP\/1\.1 400 /u);
  connection.socket.destroy();
  assert.equal(fs.existsSync(fixture.marker), false);
});

test("WebSocket rejects malformed routing hints before provider-key lookup", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer();
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const connection = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/responses`,
    `Bearer ${CHATGPT_TOKEN}`,
    { routingHint: "model=gpt test" },
  );
  assert.match(connection.headers, /^HTTP\/1\.1 400 /u);
  connection.socket.destroy();
  assert.equal(helperCallCount(fixture), 0);
});

test("WebSocket handshake timeout closes a silent upstream and frees capacity", async (t) => {
  const fixture = makeFixture(t);
  const upgradedSockets = new Set();
  const upstream = http.createServer((_incoming, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end('{"data":[]}');
  });
  upstream.on("upgrade", (_request, socket) => {
    upgradedSockets.add(socket);
    socket.once("close", () => upgradedSockets.delete(socket));
    socket.once("error", () => {});
    socket.resume();
  });
  const upstreamAddress = await listen(upstream);
  t.after(async () => {
    for (const socket of upgradedSockets) socket.destroy();
    await close(upstream);
  });
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    connectTimeoutMs: 100,
    idleTimeoutMs: 5_000,
    maxConnections: 1,
  }));

  const connection = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/responses`,
    `Bearer ${CHATGPT_TOKEN}`,
    { timeoutMs: 1_500 },
  );
  assert.match(connection.headers, /^HTTP\/1\.1 502 /u);
  assert.ok(connection.totalMs < 1_000, JSON.stringify({ totalMs: connection.totalMs }));
  connection.socket.destroy();

  const next = await request(
    `http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`,
    { headers: authHeaders() },
  );
  assert.equal(next.status, 200);
});
