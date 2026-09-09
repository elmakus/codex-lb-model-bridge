#!/usr/bin/env node

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { Transform } from "node:stream";
import { fileURLToPath } from "node:url";

const MAX_CONFIG_BYTES = 128 * 1024;
const MAX_AUTH_BYTES = 128 * 1024;
const MAX_HELPER_OUTPUT_BYTES = 16 * 1024;
const MAX_UPSTREAM_HEADERS_BYTES = 64 * 1024;
const MAX_STREAM_BYTES = 512 * 1024 * 1024;
const MAX_IDLE_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SAFE_TOKEN = /^[^\u0000-\u0020\u007f]+$/u;
const SAFE_ACTOR = /^[A-Za-z0-9._~-]{1,128}$/u;
const SAFE_HEADER_VALUE = /^[\t\x20-\x7e\x80-\xff]*$/u;
const SAFE_HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const PUBLIC_BASE_PATH = /^\/[a-f0-9]{64}\/backend-api\/codex$/u;

// Headers that are scoped to one transport hop and must be rebuilt by the
// bridge rather than copied end-to-end. Header names nominated by Connection
// are stripped dynamically as well.
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

// These application headers are owned by the bridge. The incoming ChatGPT
// bearer authenticates the local client but must never become the upstream
// bearer. Actor authorization is likewise set from bridge config.
const BRIDGE_REQUEST_HEADERS = new Set([
  "authorization",
  "host",
  "x-openai-actor-authorization",
]);

// Proxy identity is transport metadata, not Codex application metadata. The
// Codex-LB hop can legitimately trust loopback proxy headers, so values supplied
// by the desktop client must not be allowed to impersonate the bridge's network
// identity. This is intentionally separate from x-codex-* / x-openai-* headers,
// which remain transparent.
const PROXY_IDENTITY_HEADERS = new Set([
  "forwarded",
  "x-real-ip",
  "true-client-ip",
  "cf-connecting-ip",
]);

// Only used to keep logs useful without recording arbitrary path identifiers.
// Unknown roots are redacted rather than rejected; this list has no routing or
// forwarding effect.
const SAFE_LOG_ROUTE_ROOTS = new Set([
  "agent-identities",
  "alpha",
  "analytics-events",
  "images",
  "memories",
  "models",
  "opportunistic",
  "realtime",
  "responses",
  "safety",
  "thread",
]);

class BridgeError extends Error {
  constructor(code, status = 502) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

function fail(code, status = 502) {
  throw new BridgeError(code, status);
}

function openProtectedRegularFile(filePath, maximumBytes, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const metadata = fs.fstatSync(descriptor);
    if (!metadata.isFile()) fail(`${label}_not_regular`);
    if (metadata.uid !== process.getuid()) fail(`${label}_wrong_owner`);
    if ((metadata.mode & 0o077) !== 0) fail(`${label}_unsafe_mode`);
    if (metadata.nlink !== 1) fail(`${label}_unexpected_links`);
    if (metadata.size < 2 || metadata.size > maximumBytes) fail(`${label}_unsafe_size`);
    return descriptor;
  } catch (error) {
    if (descriptor != null) fs.closeSync(descriptor);
    if (error instanceof BridgeError) throw error;
    fail(`${label}_open_failed`);
  }
}

function readProtectedJson(filePath, maximumBytes, label) {
  const descriptor = openProtectedRegularFile(filePath, maximumBytes, label);
  try {
    return JSON.parse(fs.readFileSync(descriptor, "utf8"));
  } catch {
    fail(`${label}_invalid_json`);
  } finally {
    fs.closeSync(descriptor);
  }
}

function validateHelper(helperPath) {
  let descriptor;
  try {
    descriptor = fs.openSync(helperPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const metadata = fs.fstatSync(descriptor);
    if (!metadata.isFile()) fail("provider_helper_not_regular");
    if (metadata.uid !== process.getuid() && metadata.uid !== 0) fail("provider_helper_wrong_owner");
    if ((metadata.mode & 0o022) !== 0) fail("provider_helper_writable");
    if (metadata.size < 2 || metadata.size > 1024 * 1024) fail("provider_helper_unsafe_size");
    return descriptor;
  } catch (error) {
    if (descriptor != null) fs.closeSync(descriptor);
    if (error instanceof BridgeError) throw error;
    fail("provider_helper_open_failed");
  }
}

export function normalizeConfig(value) {
  if (value?.version !== 1) fail("unsupported_config_version");
  if (value.listenHost !== "127.0.0.1") fail("listen_must_be_ipv4_loopback");
  if (!Number.isInteger(value.listenPort) || value.listenPort < 0 || value.listenPort > 65535) {
    fail("invalid_listen_port");
  }
  if (typeof value.publicBasePath !== "string" || !PUBLIC_BASE_PATH.test(value.publicBasePath)) {
    fail("invalid_public_base_path");
  }
  const upstream = new URL(value.upstreamBaseUrl);
  if (upstream.protocol !== "http:" || upstream.hostname !== "127.0.0.1") {
    fail("upstream_must_be_http_ipv4_loopback");
  }
  if (!upstream.port || upstream.username || upstream.password || upstream.search || upstream.hash) {
    fail("invalid_upstream_url");
  }
  upstream.pathname = upstream.pathname.replace(/\/+$/u, "");
  if (upstream.pathname !== "/backend-api/codex") fail("invalid_upstream_base_path");

  for (const [name, candidate] of [
    ["auth_file", value.authFile],
    ["provider_helper", value.providerTokenHelper],
  ]) {
    if (typeof candidate !== "string" || !path.isAbsolute(candidate) || candidate.includes("\0")) {
      fail(`invalid_${name}`);
    }
  }
  if (typeof value.providerTokenPrefix !== "string" || !SAFE_TOKEN.test(value.providerTokenPrefix)) {
    fail("invalid_provider_token_prefix");
  }
  if (typeof value.actorAuthorization !== "string" || !SAFE_ACTOR.test(value.actorAuthorization)) {
    fail("invalid_actor_authorization");
  }

  const numberDefaults = {
    connectTimeoutMs: 10_000,
    idleTimeoutMs: 60 * 60 * 1000,
    maxConnections: 32,
    maxRequestBytes: 256 * 1024 * 1024,
    maxResponseBytes: 256 * 1024 * 1024,
    tokenTimeoutMs: 5_000,
  };
  const normalized = { ...value, upstream };
  for (const [name, defaultValue] of Object.entries(numberDefaults)) {
    const candidate = value[name] ?? defaultValue;
    if (!Number.isSafeInteger(candidate) || candidate <= 0) fail(`invalid_${name}`);
    normalized[name] = candidate;
  }
  if (normalized.maxConnections > 256) fail("max_connections_too_high");
  if (normalized.tokenTimeoutMs > 30_000 || normalized.connectTimeoutMs > 60_000) {
    fail("timeout_too_high");
  }
  if (normalized.idleTimeoutMs > MAX_IDLE_TIMEOUT_MS) fail("idle_timeout_too_high");
  if (normalized.maxRequestBytes > MAX_STREAM_BYTES || normalized.maxResponseBytes > MAX_STREAM_BYTES) {
    fail("stream_limit_too_high");
  }
  return normalized;
}

export function loadConfig(configPath) {
  return normalizeConfig(readProtectedJson(configPath, MAX_CONFIG_BYTES, "config"));
}

function currentChatGptAuthorization(config) {
  const auth = readProtectedJson(config.authFile, MAX_AUTH_BYTES, "auth");
  const token = auth?.auth_mode === "chatgpt" ? auth?.tokens?.access_token : null;
  if (typeof token !== "string" || token.length < 16 || token.length > 64 * 1024 || !SAFE_TOKEN.test(token)) {
    fail("chatgpt_auth_unavailable", 401);
  }
  return `Bearer ${token}`;
}

function rawHeaderValues(request, wantedName) {
  const result = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === wantedName) result.push(request.rawHeaders[index + 1]);
  }
  return result;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  const leftLength = Buffer.allocUnsafe(8);
  const rightLength = Buffer.allocUnsafe(8);
  try {
    leftLength.writeBigUInt64BE(BigInt(leftBuffer.length));
    rightLength.writeBigUInt64BE(BigInt(rightBuffer.length));
    const leftDigest = crypto.createHash("sha256").update(leftLength).update(leftBuffer).digest();
    const rightDigest = crypto.createHash("sha256").update(rightLength).update(rightBuffer).digest();
    try {
      return crypto.timingSafeEqual(leftDigest, rightDigest);
    } finally {
      leftDigest.fill(0);
      rightDigest.fill(0);
    }
  } finally {
    leftBuffer.fill(0);
    rightBuffer.fill(0);
    leftLength.fill(0);
    rightLength.fill(0);
  }
}

function isCanonicalWebSocketKey(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{22}==$/u.test(value)) return false;
  return Buffer.from(value, "base64").toString("base64") === value;
}

function byteLimitTransform(maximumBytes, code, status) {
  let total = 0;
  return new Transform({
    transform(chunk, _encoding, callback) {
      total += chunk.length;
      if (total > maximumBytes) {
        callback(new BridgeError(code, status));
        return;
      }
      callback(null, chunk);
    },
  });
}

async function authorizeClient(config, request) {
  const supplied = rawHeaderValues(request, "authorization");
  if (supplied.length !== 1) return false;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    let expected;
    try {
      expected = currentChatGptAuthorization(config);
    } catch {
      if (attempt === 0) {
        await new Promise((resolve) => setTimeout(resolve, 15));
        continue;
      }
      fail("client_auth_unavailable", 503);
    }
    if (safeEqual(supplied[0], expected)) return true;
    if (attempt === 0) await new Promise((resolve) => setTimeout(resolve, 15));
  }
  return false;
}

function connectionTokens(values) {
  return values
    .flatMap((value) => String(value || "").split(","))
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function appendHeader(result, name, value) {
  if (result[name] == null) {
    result[name] = value;
    return;
  }
  if (Array.isArray(result[name])) result[name].push(value);
  else result[name] = [result[name], value];
}

function connectionScopedRequestHeaders(request) {
  const result = new Set(HOP_BY_HOP_HEADERS);
  for (const token of connectionTokens(rawHeaderValues(request, "connection"))) result.add(token);
  return result;
}

function isProxyIdentityHeader(name) {
  return PROXY_IDENTITY_HEADERS.has(name) || name.startsWith("x-forwarded-");
}

function collectForwardHeaders(request) {
  const blocked = connectionScopedRequestHeaders(request);
  const collected = {};
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    const name = request.rawHeaders[index].toLowerCase();
    const value = request.rawHeaders[index + 1];
    if (blocked.has(name) || BRIDGE_REQUEST_HEADERS.has(name) || isProxyIdentityHeader(name)) continue;
    appendHeader(collected, name, value);
  }
  return collected;
}

function validateIncomingRequest(config, request) {
  if (request.rawHeaders.length / 2 > 64) fail("too_many_headers", 431);
  if (Buffer.byteLength(request.url || "") > 4096) fail("request_target_too_large", 414);
  const contentLengthValues = rawHeaderValues(request, "content-length");
  if (contentLengthValues.length > 1) fail("duplicate_content_length", 400);
  const contentLength = contentLengthValues[0];
  if (contentLength != null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(contentLength)) fail("invalid_content_length", 400);
    if (Number(contentLength) > config.maxRequestBytes) fail("request_too_large", 413);
  }
}

function providerEnvironment() {
  const runtimeDirectory = process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid()}`;
  return {
    DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS || `unix:path=${runtimeDirectory}/bus`,
    HOME: os.homedir(),
    LANG: "C.UTF-8",
    PATH: "/usr/bin:/bin",
    XDG_RUNTIME_DIR: runtimeDirectory,
  };
}

function loadProviderToken(config, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new BridgeError("provider_helper_cancelled", 499));
      return;
    }
    let helperDescriptor;
    try {
      helperDescriptor = validateHelper(config.providerTokenHelper);
    } catch (error) {
      reject(error);
      return;
    }
    let child;
    try {
      child = spawn("/usr/bin/python3", ["/proc/self/fd/3", "token"], {
        cwd: "/",
        env: providerEnvironment(),
        shell: false,
        stdio: ["ignore", "pipe", "ignore", helperDescriptor],
      });
    } catch {
      fs.closeSync(helperDescriptor);
      reject(new BridgeError("provider_helper_start_failed"));
      return;
    }
    fs.closeSync(helperDescriptor);
    let output = Buffer.alloc(0);
    let settled = false;
    let timer;
    const finish = (error, token) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      output.fill(0);
      if (error) reject(error);
      else resolve(token);
    };
    const onAbort = () => {
      child.kill("SIGKILL");
      finish(new BridgeError("provider_helper_cancelled", 499));
    };
    timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(new BridgeError("provider_helper_timeout"));
    }, config.tokenTimeoutMs);
    timer.unref?.();
    signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk) => {
      if (settled) {
        chunk.fill(0);
        return;
      }
      if (output.length + chunk.length > MAX_HELPER_OUTPUT_BYTES) {
        child.kill("SIGKILL");
        finish(new BridgeError("provider_helper_output_too_large"));
        return;
      }
      output = Buffer.concat([output, chunk]);
    });
    child.once("error", () => finish(new BridgeError("provider_helper_start_failed")));
    child.once("close", (status) => {
      if (settled) return;
      if (status !== 0) {
        finish(new BridgeError("provider_helper_failed"));
        return;
      }
      let token = output.toString("utf8");
      if (token.endsWith("\n")) token = token.slice(0, -1);
      if (token.endsWith("\r")) token = token.slice(0, -1);
      if (
        !token.startsWith(config.providerTokenPrefix)
        || token.length < config.providerTokenPrefix.length + 16
        || !SAFE_TOKEN.test(token)
      ) {
        finish(new BridgeError("provider_helper_invalid_token"));
        return;
      }
      finish(null, token);
    });
  });
}

function resolveRoute(config, requestUrl) {
  const parsed = new URL(requestUrl || "/", "http://loopback.invalid");
  if (parsed.pathname === config.publicBasePath) return { parsed, suffix: "" };
  if (!parsed.pathname.startsWith(`${config.publicBasePath}/`)) fail("route_not_found", 404);
  return { parsed, suffix: parsed.pathname.slice(config.publicBasePath.length) };
}

function destinationFor(config, suffix, search) {
  return new URL(`${config.upstream.pathname}${suffix}${search}`, config.upstream.origin);
}

function responseConnectionScopedHeaders(rawHeaders) {
  const connectionValues = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index].toLowerCase() === "connection") connectionValues.push(rawHeaders[index + 1]);
  }
  const result = new Set(HOP_BY_HOP_HEADERS);
  for (const token of connectionTokens(connectionValues)) result.add(token);
  return result;
}

function rewriteRedirectLocation(config, status, value) {
  if (status < 300 || status >= 400 || typeof value !== "string") return value;
  let target;
  try {
    target = new URL(value, config.upstream);
  } catch {
    return value;
  }
  if (target.origin !== config.upstream.origin) return value;
  const upstreamPath = config.upstream.pathname;
  if (target.pathname !== upstreamPath && !target.pathname.startsWith(`${upstreamPath}/`)) return value;
  const suffix = target.pathname.slice(upstreamPath.length);
  return `${config.publicBasePath}${suffix}${target.search}${target.hash}`;
}

function transparentResponseHeaders(config, incoming, status) {
  const blocked = responseConnectionScopedHeaders(incoming.rawHeaders || []);
  const result = {};
  const raw = incoming.rawHeaders || [];
  for (let index = 0; index < raw.length; index += 2) {
    const name = raw[index].toLowerCase();
    if (blocked.has(name)) continue;
    const value = name === "location"
      ? rewriteRedirectLocation(config, status, raw[index + 1])
      : raw[index + 1];
    appendHeader(result, name, value);
  }
  return result;
}

function sendJsonError(response, status, message) {
  if (response.destroyed || !response.writable) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const body = `${JSON.stringify({ error: { message } })}\n`;
  response.writeHead(status, {
    "cache-control": "no-store",
    connection: "close",
    "content-length": Buffer.byteLength(body),
    "content-type": "application/json",
  });
  response.end(body);
}

function socketError(socket, status, reason) {
  if (socket.destroyed || !socket.writable) return socket.destroy();
  const body = `${JSON.stringify({ error: { message: reason } })}\n`;
  const statusText = new Map([
    [400, "Bad Request"],
    [401, "Unauthorized"],
    [403, "Forbidden"],
    [404, "Not Found"],
    [413, "Payload Too Large"],
    [414, "URI Too Long"],
    [431, "Request Header Fields Too Large"],
    [502, "Bad Gateway"],
    [503, "Service Unavailable"],
  ]).get(status) || "Bad Gateway";
  socket.end([
    `HTTP/1.1 ${status} ${statusText}`,
    "Connection: close",
    "Content-Type: application/json",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "Cache-Control: no-store",
    "",
    body,
  ].join("\r\n"));
}

function parseHandshake(buffer) {
  const marker = buffer.indexOf("\r\n\r\n");
  if (marker < 0) return null;
  const headerBlock = buffer.subarray(0, marker).toString("latin1");
  const lines = headerBlock.split("\r\n");
  const statusMatch = /^HTTP\/1\.[01] ([0-9]{3})(?: |$)/u.exec(lines.shift() || "");
  if (!statusMatch) fail("invalid_websocket_status");
  const headers = [];
  for (const line of lines) {
    if (/^[ \t]/u.test(line)) fail("folded_websocket_header");
    const separator = line.indexOf(":");
    if (separator <= 0) fail("invalid_websocket_header");
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!SAFE_HEADER_NAME.test(name)) fail("invalid_websocket_header_name");
    if (!SAFE_HEADER_VALUE.test(value)) fail("invalid_websocket_header_value");
    headers.push([name, value]);
  }
  return { status: Number(statusMatch[1]), headers, rest: buffer.subarray(marker + 4) };
}

function handshakeValues(handshake, wantedName) {
  return handshake.headers.filter(([name]) => name === wantedName).map(([, value]) => value);
}

function websocketAccept(key) {
  return crypto.createHash("sha1").update(key + WEBSOCKET_GUID).digest("base64");
}

function safeLog(logger, event, fields = {}) {
  try {
    logger({ event, ...fields });
  } catch {
    // Diagnostics must never alter proxy behavior.
  }
}

function routeLabel(method, suffix) {
  const segments = String(suffix || "").split("/").filter(Boolean);
  let pathLabel = "/";
  if (segments.length > 0) {
    const root = segments[0];
    pathLabel = SAFE_LOG_ROUTE_ROOTS.has(root)
      ? `/${root}${segments.length > 1 ? "/<redacted>" : ""}`
      : "/<redacted>";
  }
  return `${method || "UNKNOWN"} ${pathLabel}`;
}

export function createBridge(rawConfig, options = {}) {
  const config = normalizeConfig(rawConfig);
  const logger = options.logger || ((record) => process.stderr.write(`${JSON.stringify(record)}\n`));
  const agent = new http.Agent({ keepAlive: true, maxSockets: config.maxConnections });
  const sockets = new Set();
  let active = 0;

  const reserve = () => {
    if (active >= config.maxConnections) return false;
    active += 1;
    return true;
  };
  const releaseOnce = () => {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      active = Math.max(0, active - 1);
    };
  };

  const server = http.createServer({ maxHeaderSize: 16 * 1024 }, async (request, response) => {
    let route = "unknown";
    let release = () => {};
    const controller = new AbortController();
    const onRequestGone = () => controller.abort();
    const onResponseGone = () => {
      if (!response.writableEnded) controller.abort();
    };
    request.once("aborted", onRequestGone);
    request.once("error", onRequestGone);
    response.once("close", onResponseGone);
    response.once("error", onRequestGone);
    const removeClientListeners = () => {
      request.removeListener("aborted", onRequestGone);
      response.removeListener("close", onResponseGone);
    };

    try {
      const { parsed, suffix } = resolveRoute(config, request.url);
      route = routeLabel(request.method, suffix);
      validateIncomingRequest(config, request);
      if (!(await authorizeClient(config, request))) fail("client_auth_rejected", 401);
      if (!reserve()) fail("bridge_busy", 503);
      release = releaseOnce();
      const providerToken = await loadProviderToken(config, { signal: controller.signal });
      if (controller.signal.aborted || request.destroyed || response.destroyed) {
        fail("client_disconnected", 499);
      }

      const destination = destinationFor(config, suffix, parsed.search);
      const headers = collectForwardHeaders(request);
      headers.authorization = `Bearer ${providerToken}`;
      headers["x-openai-actor-authorization"] = config.actorAuthorization;

      const upstreamRequest = http.request(destination, {
        agent,
        headers,
        method: request.method,
      });
      const requestLimiter = byteLimitTransform(config.maxRequestBytes, "request_too_large", 413);
      let responseLimiter;
      let upstreamResponse;
      let settled = false;
      let requestFinished = false;
      let responseFinished = false;
      let responseStatus = 502;
      const connectTimer = setTimeout(
        () => upstreamRequest.destroy(new Error("connect timeout")),
        config.connectTimeoutMs,
      );
      connectTimer.unref?.();

      const cleanup = () => {
        clearTimeout(connectTimer);
        controller.signal.removeEventListener("abort", onAbort);
        removeClientListeners();
      };
      const finish = () => {
        if (settled) return false;
        settled = true;
        cleanup();
        release();
        return true;
      };
      const failTransaction = (status, message, { send = true } = {}) => {
        if (!finish()) return;
        request.unpipe(requestLimiter);
        requestLimiter.destroy();
        if (!request.destroyed) request.resume();
        responseLimiter?.destroy();
        upstreamResponse?.destroy();
        upstreamRequest.destroy();
        if (send) sendJsonError(response, status, message);
        else response.destroy();
      };
      const completeIfFinished = () => {
        if (!requestFinished || !responseFinished || !finish()) return;
        safeLog(logger, "request_complete", { route, status: responseStatus });
      };
      const onAbort = () => failTransaction(502, "model provider request failed", { send: false });
      controller.signal.addEventListener("abort", onAbort, { once: true });
      if (controller.signal.aborted) onAbort();

      upstreamRequest.once("socket", (socket) => {
        if (!socket.connecting) clearTimeout(connectTimer);
        else socket.once("connect", () => clearTimeout(connectTimer));
      });
      upstreamRequest.setTimeout(config.idleTimeoutMs, () => {
        failTransaction(502, "model provider request failed");
      });
      upstreamRequest.once("finish", () => {
        requestFinished = true;
        completeIfFinished();
      });
      upstreamRequest.once("error", () => {
        failTransaction(502, "model provider request failed");
      });
      requestLimiter.once("error", (error) => {
        const status = error instanceof BridgeError ? error.status : 413;
        failTransaction(status, "request is too large");
      });
      response.once("finish", () => {
        responseFinished = true;
        completeIfFinished();
      });
      upstreamRequest.once("response", (incoming) => {
        upstreamResponse = incoming;
        clearTimeout(connectTimer);
        const status = upstreamResponse.statusCode || 502;
        // A 401 here authenticates the bridge-to-provider hop, not the user's
        // local ChatGPT session. Mask it so Codex does not invalidate its own
        // login. Other application statuses, including 403, remain transparent.
        if (status === 401 || status === 101) {
          failTransaction(502, "model provider request failed");
          safeLog(logger, "request_complete", { route, status: 502 });
          return;
        }
        responseStatus = status;
        response.writeHead(status, transparentResponseHeaders(config, upstreamResponse, status));
        response.flushHeaders?.();
        responseLimiter = byteLimitTransform(config.maxResponseBytes, "response_too_large", 502);
        responseLimiter.once("error", () => {
          failTransaction(502, "model provider response is too large");
        });
        upstreamResponse.once("aborted", () => {
          failTransaction(502, "model provider request failed");
        });
        upstreamResponse.once("error", () => {
          failTransaction(502, "model provider request failed");
        });
        upstreamResponse.once("close", () => {
          if (!upstreamResponse.complete) failTransaction(502, "model provider request failed");
        });
        upstreamResponse.pipe(responseLimiter).pipe(response);
      });
      request.pipe(requestLimiter).pipe(upstreamRequest);
    } catch (error) {
      removeClientListeners();
      release();
      const status = error instanceof BridgeError ? error.status : 502;
      const normalizedStatus = status === 499 ? 502 : status;
      const message = normalizedStatus === 401
        ? "unauthorized"
        : normalizedStatus === 403
          ? "forbidden"
          : normalizedStatus === 404
            ? "not found"
            : normalizedStatus === 413
              ? "request is too large"
              : normalizedStatus === 503
                ? "model bridge unavailable"
                : "model provider request failed";
      sendJsonError(response, normalizedStatus, message);
      safeLog(logger, "request_rejected", { route, status: normalizedStatus });
    }
  });

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  server.on("upgrade", async (request, clientSocket, head) => {
    let route = "unknown";
    let release = () => {};
    const controller = new AbortController();
    const onClientGone = () => controller.abort();
    clientSocket.once("error", onClientGone);
    clientSocket.once("close", onClientGone);
    clientSocket.pause();

    try {
      const { parsed, suffix } = resolveRoute(config, request.url);
      route = routeLabel(request.method, suffix);
      if (request.method !== "GET") fail("invalid_websocket_method", 400);
      if (request.rawHeaders.length / 2 > 64) fail("too_many_headers", 431);
      if (Buffer.byteLength(request.url || "") > 4096) fail("request_target_too_large", 414);

      const connection = rawHeaderValues(request, "connection");
      const upgrade = rawHeaderValues(request, "upgrade");
      const keyValues = rawHeaderValues(request, "sec-websocket-key");
      const versionValues = rawHeaderValues(request, "sec-websocket-version");
      if (
        connection.length < 1
        || !connectionTokens(connection).includes("upgrade")
        || upgrade.length !== 1
        || upgrade[0].toLowerCase() !== "websocket"
        || keyValues.length !== 1
        || !isCanonicalWebSocketKey(keyValues[0])
        || versionValues.length !== 1
        || versionValues[0] !== "13"
      ) fail("invalid_websocket_upgrade", 400);

      if (!(await authorizeClient(config, request))) fail("client_auth_rejected", 401);
      if (!reserve()) fail("bridge_busy", 503);
      release = releaseOnce();
      const providerToken = await loadProviderToken(config, { signal: controller.signal });
      if (controller.signal.aborted || clientSocket.destroyed) fail("client_disconnected", 499);

      const destination = destinationFor(config, suffix, parsed.search);
      const headers = collectForwardHeaders(request);
      headers.host = destination.host;
      headers.authorization = `Bearer ${providerToken}`;
      headers["x-openai-actor-authorization"] = config.actorAuthorization;
      headers.connection = "Upgrade";
      headers.upgrade = "websocket";

      const upstreamSocket = net.createConnection({ host: destination.hostname, port: Number(destination.port) });
      upstreamSocket.setKeepAlive(true, 15_000);
      upstreamSocket.setTimeout(config.idleTimeoutMs, () => upstreamSocket.destroy(new Error("idle timeout")));
      sockets.add(upstreamSocket);
      let handshaken = false;
      let handshakeBuffer = Buffer.alloc(0);
      const timeout = setTimeout(
        () => upstreamSocket.destroy(new Error("connect timeout")),
        config.connectTimeoutMs,
      );
      timeout.unref?.();
      const onAbort = () => {
        upstreamSocket.destroy();
        release();
      };
      controller.signal.addEventListener("abort", onAbort, { once: true });
      const closeBoth = () => {
        clearTimeout(timeout);
        upstreamSocket.destroy();
        clientSocket.destroy();
        release();
      };
      upstreamSocket.once("error", () => {
        if (!handshaken) socketError(clientSocket, 502, "model provider request failed");
        else clientSocket.destroy();
        release();
      });
      upstreamSocket.once("close", () => {
        controller.signal.removeEventListener("abort", onAbort);
        sockets.delete(upstreamSocket);
        if (handshaken) clientSocket.end();
        release();
      });
      clientSocket.once("close", () => {
        upstreamSocket.destroy();
        release();
      });
      upstreamSocket.once("connect", () => {
        const prelude = [
          `GET ${destination.pathname}${destination.search} HTTP/1.1`,
          ...Object.entries(headers).flatMap(([name, value]) => (
            Array.isArray(value) ? value.map((entry) => `${name}: ${entry}`) : [`${name}: ${value}`]
          )),
          "",
          "",
        ].join("\r\n");
        upstreamSocket.write(prelude);
        if (head?.length) upstreamSocket.write(head);
      });
      upstreamSocket.on("data", function onHandshake(chunk) {
        if (handshaken) return;
        handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);
        if (handshakeBuffer.length > MAX_UPSTREAM_HEADERS_BYTES) {
          closeBoth();
          return;
        }
        let parsedHandshake;
        try {
          parsedHandshake = parseHandshake(handshakeBuffer);
        } catch {
          closeBoth();
          return;
        }
        if (!parsedHandshake) return;

        const expectedAccept = websocketAccept(keyValues[0]);
        const acceptValues = handshakeValues(parsedHandshake, "sec-websocket-accept");
        const upgradeValues = handshakeValues(parsedHandshake, "upgrade");
        const connectionValues = handshakeValues(parsedHandshake, "connection");
        if (
          parsedHandshake.status !== 101
          || acceptValues.length !== 1
          || upgradeValues.length !== 1
          || upgradeValues[0].toLowerCase() !== "websocket"
          || !connectionTokens(connectionValues).includes("upgrade")
          || !safeEqual(acceptValues[0], expectedAccept)
        ) {
          upstreamSocket.removeListener("data", onHandshake);
          upstreamSocket.destroy();
          socketError(clientSocket, 502, "model provider request failed");
          release();
          return;
        }

        const selectedProtocols = handshakeValues(parsedHandshake, "sec-websocket-protocol");
        const requestedProtocols = rawHeaderValues(request, "sec-websocket-protocol")
          .flatMap((value) => value.split(","))
          .map((value) => value.trim())
          .filter(Boolean);
        if (
          selectedProtocols.length > 1
          || (selectedProtocols.length === 1 && !requestedProtocols.includes(selectedProtocols[0]))
        ) {
          upstreamSocket.removeListener("data", onHandshake);
          upstreamSocket.destroy();
          socketError(clientSocket, 502, "model provider request failed");
          release();
          return;
        }

        const blocked = new Set(HOP_BY_HOP_HEADERS);
        blocked.add("sec-websocket-accept");
        for (const token of connectionTokens(connectionValues)) blocked.add(token);
        const responseLines = [
          "HTTP/1.1 101 Switching Protocols",
          "Upgrade: websocket",
          "Connection: Upgrade",
          `Sec-WebSocket-Accept: ${acceptValues[0]}`,
        ];
        for (const [name, value] of parsedHandshake.headers) {
          if (blocked.has(name)) continue;
          if (name === "sec-websocket-protocol" && !requestedProtocols.length) continue;
          if (name === "sec-websocket-extensions" && rawHeaderValues(request, name).length === 0) continue;
          responseLines.push(`${name}: ${value}`);
        }
        responseLines.push("", "");

        upstreamSocket.removeListener("data", onHandshake);
        handshaken = true;
        clearTimeout(timeout);
        clientSocket.write(responseLines.join("\r\n"));
        if (parsedHandshake.rest.length) clientSocket.write(parsedHandshake.rest);
        upstreamSocket.pipe(clientSocket);
        clientSocket.pipe(upstreamSocket);
        clientSocket.resume();
        safeLog(logger, "websocket_connected", { route });
      });
    } catch (error) {
      release();
      const status = error instanceof BridgeError ? error.status : 502;
      const normalizedStatus = status === 499 ? 502 : status;
      socketError(
        clientSocket,
        normalizedStatus,
        normalizedStatus === 401
          ? "unauthorized"
          : normalizedStatus === 404
            ? "not found"
            : "model provider request failed",
      );
      safeLog(logger, "websocket_rejected", { route, status: normalizedStatus });
    }
  });

  server.on("clientError", (_error, socket) => socket.destroy());
  server.maxConnections = config.maxConnections + 8;
  server.maxHeadersCount = 64;
  server.headersTimeout = 15_000;
  server.requestTimeout = 0;
  server.keepAliveTimeout = 5_000;

  return {
    config,
    server,
    async listen() {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen({ exclusive: true, host: config.listenHost, port: config.listenPort }, resolve);
      });
      const address = server.address();
      safeLog(logger, "bridge_ready", { host: address.address, port: address.port });
      return address;
    },
    async close() {
      agent.destroy();
      const closed = new Promise((resolve) => server.close(resolve));
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections?.();
      await closed;
    },
  };
}

async function main() {
  const configPath = process.argv[2];
  if (!configPath) fail("usage_bridge_config");
  const bridge = createBridge(loadConfig(configPath));
  await bridge.listen();
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    const forced = setTimeout(() => process.exit(1), 5_000);
    forced.unref?.();
    await bridge.close();
    process.exit(0);
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    process.stderr.write(`${JSON.stringify({ event: "bridge_start_failed" })}\n`);
    process.exit(1);
  });
}
