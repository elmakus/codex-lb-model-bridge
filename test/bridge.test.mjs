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
    maxResponseBytes: 1024 * 1024,
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
        rawHeaders: response.rawHeaders,
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

test("configuration keeps the bridge and upstream pinned to IPv4 loopback Codex namespace", async (t) => {
  const fixture = makeFixture(t);
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, {
      upstreamBaseUrl: "http://198.51.100.10:18080/backend-api/codex",
    })),
    /upstream_must_be_http_ipv4_loopback/u,
  );
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, {
      upstreamBaseUrl: "http://127.0.0.1:18080/v1",
    })),
    /invalid_upstream_base_path/u,
  );
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, {
      publicBasePath: "/guessable/backend-api/codex",
    })),
    /invalid_public_base_path/u,
  );
  assert.throws(
    () => normalizeConfig(configFor(fixture, 18080, { maxRequestBytes: 513 * 1024 * 1024 })),
    /stream_limit_too_high/u,
  );

  const configPath = path.join(fixture.directory, "config.json");
  fs.writeFileSync(configPath, JSON.stringify(configFor(fixture, 18080)), { mode: 0o644 });
  assert.throws(() => loadConfig(configPath), /config_unsafe_mode/u);
  fs.chmodSync(configPath, 0o600);
  assert.equal(loadConfig(configPath).listenHost, "127.0.0.1");
});

test("unknown Codex routes, methods, body types and application headers pass transparently", async (t) => {
  const fixture = makeFixture(t);
  const received = [];
  const upstream = http.createServer((incoming, response) => {
    const chunks = [];
    incoming.on("data", (chunk) => chunks.push(chunk));
    incoming.on("end", () => {
      received.push({
        body: Buffer.concat(chunks),
        headers: incoming.headers,
        method: incoming.method,
        url: incoming.url,
      });
      response.writeHead(201, {
        "content-type": "application/octet-stream",
        location: "/backend-api/codex/realtime/calls/call-123",
        "set-cookie": ["one=1; Path=/", "two=2; Path=/"],
        "x-codex-imagegen-request-id": "image-request-123",
        "x-future-codex-response": "future-response",
        connection: "close, x-upstream-hop",
        "x-upstream-hop": "must-not-cross-hop",
      });
      response.end("opaque-response");
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const logs = [];
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port), logs);
  const base = `http://127.0.0.1:${address.port}${PUBLIC_BASE}`;
  const body = Buffer.from([0, 1, 2, 3, 255]);

  const result = await request(`${base}/future/new-feature?mode=opaque`, {
    method: "PATCH",
    headers: authHeaders({
      "content-type": "application/octet-stream",
      "content-encoding": "br",
      cookie: "native-client-cookie=1",
      "x-api-key": "native-client-header",
      "x-codex-image-turn-id": "turn-123",
      "x-openai-memgen-request": "memory-123",
      "x-oai-attestation": "attestation-123",
      "x-future-codex-header": "future-request",
      "x-openai-actor-authorization": "must-be-overwritten",
      forwarded: "for=198.51.100.10;proto=https",
      "x-forwarded-for": "198.51.100.10",
      "x-forwarded-proto": "https",
      "x-forwarded-future": "transport-owned",
      "x-real-ip": "198.51.100.10",
      "true-client-ip": "198.51.100.10",
      "cf-connecting-ip": "198.51.100.10",
      connection: "close, x-client-hop",
      "x-client-hop": "must-not-cross-hop",
    }),
  }, body);

  assert.equal(result.status, 201);
  assert.equal(result.body, "opaque-response");
  // Location on a non-redirect response is application data and must remain untouched.
  assert.equal(result.headers.location, "/backend-api/codex/realtime/calls/call-123");
  assert.deepEqual(result.headers["set-cookie"], ["one=1; Path=/", "two=2; Path=/"]);
  assert.equal(result.headers["x-codex-imagegen-request-id"], "image-request-123");
  assert.equal(result.headers["x-future-codex-response"], "future-response");
  assert.equal(result.headers["x-upstream-hop"], undefined);

  assert.equal(received.length, 1);
  assert.equal(received[0].method, "PATCH");
  assert.equal(received[0].url, "/backend-api/codex/future/new-feature?mode=opaque");
  assert.deepEqual(received[0].body, body);
  assert.equal(received[0].headers.authorization, `Bearer ${PROVIDER_TOKEN}`);
  assert.equal(received[0].headers["x-openai-actor-authorization"], "codex-lb");
  for (const [name, value] of Object.entries({
    cookie: "native-client-cookie=1",
    "x-api-key": "native-client-header",
    "x-codex-image-turn-id": "turn-123",
    "x-openai-memgen-request": "memory-123",
    "x-oai-attestation": "attestation-123",
    "x-future-codex-header": "future-request",
  })) {
    assert.equal(received[0].headers[name], value);
  }
  for (const name of [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-future",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-client-hop",
  ]) {
    assert.equal(received[0].headers[name], undefined, name);
  }
  assert.notEqual(received[0].headers.host, `127.0.0.1:${address.port}`);
  assert.doesNotMatch(JSON.stringify(received), new RegExp(CHATGPT_TOKEN, "u"));
  assert.doesNotMatch(JSON.stringify(logs), /chatgpt-test-token|synthetic-provider/u);
  assert.deepEqual(logs.at(-1), {
    event: "request_complete",
    route: "PATCH /<redacted>",
    status: 201,
  });
});

test("known Codex endpoints remain ordinary routes rather than special cases", async (t) => {
  const fixture = makeFixture(t);
  const seen = [];
  const upstream = http.createServer((incoming, response) => {
    incoming.resume();
    incoming.once("end", () => {
      seen.push(`${incoming.method} ${incoming.url}`);
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true}');
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const base = `http://127.0.0.1:${address.port}${PUBLIC_BASE}`;

  const cases = [
    ["GET", "/models", ""],
    ["POST", "/responses", "{}"],
    ["POST", "/responses/compact", "{}"],
    ["POST", "/alpha/search", "{}"],
    ["POST", "/images/generations", "{}"],
    ["POST", "/images/edits", "{}"],
    ["POST", "/memories/trace_summarize", "{}"],
    ["POST", "/realtime/calls", "{}"],
    ["POST", "/thread/goal/get", "{}"],
    ["POST", "/analytics-events/events", "{}"],
    ["POST", "/safety/arc", "{}"],
    ["GET", "/agent-identities/jwks", ""],
    ["GET", "/opportunistic/admission", ""],
    ["GET", "", ""],
  ];
  for (const [method, suffix, body] of cases) {
    const result = await request(`${base}${suffix}`, {
      method,
      headers: authHeaders(body ? { "content-type": "application/json" } : {}),
    }, body);
    assert.equal(result.status, 200, `${method} ${suffix}`);
  }
  assert.deepEqual(seen, cases.map(([method, suffix]) => (
    `${method} /backend-api/codex${suffix}`
  )));
});

test("outside-namespace and wrong-auth requests fail before provider lookup", async (t) => {
  const fixture = makeFixture(t);
  let upstreamCalls = 0;
  const upstream = http.createServer((_incoming, response) => {
    upstreamCalls += 1;
    response.end("unexpected");
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));

  const outside = await request(`http://127.0.0.1:${address.port}/backend-api/codex/models`, {
    headers: authHeaders(),
  });
  assert.equal(outside.status, 404);

  const sibling = await request(`http://127.0.0.1:${address.port}/${"a".repeat(64)}/backend-api/accounts`, {
    headers: authHeaders(),
  });
  assert.equal(sibling.status, 404);

  const wrong = await request(`http://127.0.0.1:${address.port}${PUBLIC_BASE}/models`, {
    headers: { authorization: "Bearer wrong" },
  });
  assert.equal(wrong.status, 401);
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

test("routing hints and future metadata are forwarded opaquely", async (t) => {
  const fixture = makeFixture(t);
  let observed;
  const upstream = http.createServer((incoming, response) => {
    observed = incoming.headers;
    incoming.resume();
    incoming.once("end", () => response.end("ok"));
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const result = await request(
    `http://127.0.0.1:${address.port}${PUBLIC_BASE}/responses`,
    {
      method: "POST",
      headers: authHeaders({
        "content-type": "application/json",
        "x-codex-routing-hint": "future-format=with spaces;anything=goes",
        "x-codex-turn-state": "opaque-turn-state",
      }),
    },
    "{}",
  );
  assert.equal(result.status, 200);
  assert.equal(observed["x-codex-routing-hint"], "future-format=with spaces;anything=goes");
  assert.equal(observed["x-codex-turn-state"], "opaque-turn-state");
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

  assert.equal((await request(url, { headers: authHeaders() })).status, 200);

  const rotatedChatGptToken = "chatgpt-rotated-token-that-is-current-now";
  fs.writeFileSync(fixture.authFile, JSON.stringify({
    auth_mode: "chatgpt",
    tokens: { access_token: rotatedChatGptToken },
  }), { mode: 0o600 });
  const rotatedProviderToken = "synthetic-provider-rotated-token-that-is-current-now";
  writeProviderHelper(fixture, { providerToken: rotatedProviderToken });

  assert.equal((await request(url, {
    headers: { authorization: `Bearer ${rotatedChatGptToken}` },
  })).status, 200);
  assert.equal((await request(url, { headers: authHeaders() })).status, 401);
  assert.deepEqual(observed, [
    `Bearer ${PROVIDER_TOKEN}`,
    `Bearer ${rotatedProviderToken}`,
  ]);
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

test("declared and streamed request limits remain enforced without leaking capacity", async (t) => {
  const fixture = makeFixture(t);
  let calls = 0;
  const upstream = http.createServer((incoming, response) => {
    calls += 1;
    incoming.resume();
    incoming.once("end", () => response.end("ok"));
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
    maxRequestBytes: 16,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/future/upload`;

  const declared = await request(url, {
    method: "POST",
    headers: authHeaders({ "content-length": "64" }),
  });
  assert.equal(declared.status, 413);
  assert.equal(calls, 0);

  const streamed = await request(url, {
    method: "POST",
    headers: authHeaders(),
  }, "x".repeat(64));
  assert.equal(streamed.status, 413);

  const next = await request(url, {
    method: "POST",
    headers: authHeaders(),
  }, "small");
  assert.equal(next.status, 200);
});

test("SSE remains incremental and oversized responses terminate without leaking capacity", async (t) => {
  const fixture = makeFixture(t);
  let mode = "sse";
  const upstream = http.createServer((_incoming, response) => {
    if (mode === "sse") {
      response.writeHead(200, { "content-type": "text/event-stream", "x-future-stream": "yes" });
      response.write("data: first\n\n");
      setTimeout(() => response.end("data: second\n\n"), 120);
      return;
    }
    if (mode === "oversized") {
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.end("x".repeat(64));
      return;
    }
    response.end("ok");
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
    maxResponseBytes: 32,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/responses`;

  const streamed = await request(url, { method: "POST", headers: authHeaders() });
  assert.equal(streamed.status, 200);
  assert.equal(streamed.body, "data: first\n\ndata: second\n\n");
  assert.equal(streamed.headers["x-future-stream"], "yes");
  assert.ok(streamed.firstChunkMs < streamed.totalMs - 50, JSON.stringify(streamed));

  mode = "oversized";
  const oversized = await requestThroughClose(url, { method: "POST", headers: authHeaders() });
  assert.equal(oversized.status, 200);
  assert.equal(oversized.completed, false);
  assert.ok(oversized.body.length <= 32);

  mode = "ok";
  const next = await request(url, { method: "POST", headers: authHeaders() });
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
    response.end("ok");
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port, {
    maxConnections: 1,
  }));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/responses`;

  await new Promise((resolve, reject) => {
    const call = http.request(url, { method: "POST", headers: authHeaders() }, (response) => {
      response.once("data", () => response.destroy());
      response.once("close", resolve);
    });
    call.once("error", reject);
    call.end();
  });
  await waitFor(() => firstClosed);
  const next = await request(url, { method: "POST", headers: authHeaders() });
  assert.equal(next.status, 200);
});

test("redirects inside the Codex namespace are rewritten through the secret prefix", async (t) => {
  const fixture = makeFixture(t);
  let mode = "relative";
  const upstream = http.createServer((_incoming, response) => {
    if (mode === "relative") {
      response.writeHead(302, { location: "/backend-api/codex/future-location" });
    } else if (mode === "absolute") {
      response.writeHead(307, {
        location: `http://127.0.0.1:${upstream.address().port}/backend-api/codex/next?x=1#fragment`,
      });
    } else if (mode === "external") {
      response.writeHead(302, { location: "https://example.com/elsewhere" });
    }
    response.end();
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/future/redirect`;

  const relative = await request(url, { headers: authHeaders() });
  assert.equal(relative.status, 302);
  assert.equal(relative.headers.location, `${PUBLIC_BASE}/future-location`);

  mode = "absolute";
  const absolute = await request(url, { headers: authHeaders() });
  assert.equal(absolute.status, 307);
  assert.equal(absolute.headers.location, `${PUBLIC_BASE}/next?x=1#fragment`);

  mode = "external";
  const external = await request(url, { headers: authHeaders() });
  assert.equal(external.status, 302);
  assert.equal(external.headers.location, "https://example.com/elsewhere");
});

test("only provider 401 is masked; application 403 remains transparent", async (t) => {
  const fixture = makeFixture(t);
  let status = 401;
  const upstream = http.createServer((_incoming, response) => {
    response.writeHead(status, {
      "content-type": "application/json",
      "www-authenticate": "Bearer provider-realm",
      "x-policy-detail": "preserve-on-403",
    });
    response.end('{"error":{"code":"policy_denied"}}');
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));
  const url = `http://127.0.0.1:${address.port}${PUBLIC_BASE}/future/status`;

  const unauthorized = await request(url, { headers: authHeaders() });
  assert.equal(unauthorized.status, 502);
  assert.equal(unauthorized.headers["www-authenticate"], undefined);
  assert.doesNotMatch(unauthorized.body, /policy_denied/u);

  status = 403;
  const forbidden = await request(url, { headers: authHeaders() });
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.headers["x-policy-detail"], "preserve-on-403");
  assert.equal(forbidden.headers["www-authenticate"], "Bearer provider-realm");
  assert.equal(forbidden.body, '{"error":{"code":"policy_denied"}}');
});

function websocketHandshake(port, requestPath, authorization, options = {}) {
  return new Promise((resolve, reject) => {
    const key = options.key || crypto.randomBytes(16).toString("base64");
    const started = Date.now();
    const socket = net.createConnection({ host: "127.0.0.1", port });
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("websocket handshake timed out"));
    }, options.timeoutMs || 2_000);
    timer.unref?.();
    socket.once("error", reject);
    socket.once("connect", () => {
      const headers = [
        `GET ${requestPath} HTTP/1.1`,
        `Host: 127.0.0.1:${port}`,
        "Connection: Upgrade, X-Client-Hop",
        "Upgrade: websocket",
        "X-Client-Hop: must-not-cross-hop",
        "Sec-WebSocket-Version: 13",
        `Sec-WebSocket-Key: ${key}`,
        `Authorization: ${authorization}`,
        "Cookie: native-ws-cookie=1",
        "X-Api-Key: native-ws-header",
        "X-Future-Codex-WS: future-ws-request",
        "X-OpenAI-Actor-Authorization: must-be-overwritten",
        "Forwarded: for=198.51.100.10;proto=https",
        "X-Forwarded-For: 198.51.100.10",
        "X-Forwarded-Future: transport-owned",
        "X-Real-IP: 198.51.100.10",
        "True-Client-IP: 198.51.100.10",
        "CF-Connecting-IP: 198.51.100.10",
        "",
        "",
      ];
      socket.write(headers.join("\r\n"));
    });
    socket.on("data", function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      const marker = buffer.indexOf("\r\n\r\n");
      if (marker < 0) return;
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

test("WebSocket upgrades remain transparent while proxy identity and dynamic log paths are controlled", async (t) => {
  const fixture = makeFixture(t);
  const observed = {};
  const upstream = http.createServer();
  upstream.on("upgrade", (incoming, socket) => {
    observed.url = incoming.url;
    observed.headers = incoming.headers;
    const accept = crypto.createHash("sha1")
      .update(incoming.headers["sec-websocket-key"] + WS_GUID)
      .digest("base64");
    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Upgrade: websocket",
      "Connection: Upgrade, X-Upstream-Hop",
      `Sec-WebSocket-Accept: ${accept}`,
      "Set-Cookie: ws-one=1",
      "Set-Cookie: ws-two=2",
      "X-Future-Codex-WS-Response: future-ws-response",
      "X-Upstream-Hop: must-not-cross-hop",
      "",
      "",
    ].join("\r\n"));
    socket.write(Buffer.from([0x81, 0x02, 0x4f, 0x4b]));
    socket.once("data", (chunk) => {
      observed.clientFrame = Buffer.from(chunk);
      socket.end();
    });
  });
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const logs = [];
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port), logs);
  const sensitiveCallId = "call-sensitive-id-123";

  const connection = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/${sensitiveCallId}?mode=future`,
    `Bearer ${CHATGPT_TOKEN}`,
  );
  assert.match(connection.headers, /^HTTP\/1\.1 101 /u);
  assert.match(connection.headers, /set-cookie: ws-one=1/iu);
  assert.match(connection.headers, /set-cookie: ws-two=2/iu);
  assert.match(connection.headers, /x-future-codex-ws-response: future-ws-response/iu);
  assert.doesNotMatch(connection.headers, /x-upstream-hop/iu);

  let serverFrame = connection.rest;
  if (serverFrame.length) {
    connection.socket.resume();
  } else {
    const nextData = new Promise((resolve) => connection.socket.once("data", resolve));
    connection.socket.resume();
    serverFrame = await nextData;
  }
  assert.deepEqual(Buffer.from(serverFrame), Buffer.from([0x81, 0x02, 0x4f, 0x4b]));
  const clientFrame = Buffer.from([0x81, 0x80, 0, 0, 0, 0]);
  connection.socket.write(clientFrame);
  await new Promise((resolve) => connection.socket.once("close", resolve));

  assert.equal(observed.url, `/backend-api/codex/${sensitiveCallId}?mode=future`);
  assert.equal(observed.headers.authorization, `Bearer ${PROVIDER_TOKEN}`);
  assert.equal(observed.headers["x-openai-actor-authorization"], "codex-lb");
  assert.equal(observed.headers.cookie, "native-ws-cookie=1");
  assert.equal(observed.headers["x-api-key"], "native-ws-header");
  assert.equal(observed.headers["x-future-codex-ws"], "future-ws-request");
  for (const name of [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-future",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-client-hop",
  ]) {
    assert.equal(observed.headers[name], undefined, name);
  }
  assert.deepEqual(observed.clientFrame, clientFrame);
  assert.ok(logs.some((entry) => (
    entry.event === "websocket_connected" && entry.route === "GET /<redacted>"
  )));
  assert.doesNotMatch(JSON.stringify(logs), /call-sensitive-id-123/u);
  assert.doesNotMatch(JSON.stringify(logs), /chatgpt-test-token|synthetic-provider/u);
});

test("WebSocket still validates the transport handshake and local ChatGPT auth", async (t) => {
  const fixture = makeFixture(t);
  const upstream = http.createServer();
  const upstreamAddress = await listen(upstream);
  t.after(() => close(upstream));
  const { address } = await startBridge(t, configFor(fixture, upstreamAddress.port));

  const wrong = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/future/ws`,
    "Bearer wrong",
  );
  assert.match(wrong.headers, /^HTTP\/1\.1 401 /u);
  wrong.socket.destroy();
  assert.equal(helperCallCount(fixture), 0);

  const canonical = crypto.randomBytes(16).toString("base64");
  const malformed = await websocketHandshake(
    address.port,
    `${PUBLIC_BASE}/future/ws`,
    `Bearer ${CHATGPT_TOKEN}`,
    { key: `${canonical}!` },
  );
  assert.match(malformed.headers, /^HTTP\/1\.1 400 /u);
  malformed.socket.destroy();
  assert.equal(helperCallCount(fixture), 0);

  const outside = await websocketHandshake(
    address.port,
    "/backend-api/codex/responses",
    `Bearer ${CHATGPT_TOKEN}`,
  );
  assert.match(outside.headers, /^HTTP\/1\.1 404 /u);
  outside.socket.destroy();
  assert.equal(helperCallCount(fixture), 0);
});

test("WebSocket handshake timeout closes a silent upstream and frees capacity", async (t) => {
  const fixture = makeFixture(t);
  const upgradedSockets = new Set();
  const upstream = http.createServer((_incoming, response) => response.end("ok"));
  upstream.on("upgrade", (_incoming, socket) => {
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
