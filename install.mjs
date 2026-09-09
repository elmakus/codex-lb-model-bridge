#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { normalizeConfig } from "./bridge.mjs";

const modulePath = fileURLToPath(import.meta.url);
const defaultSourceDirectory = path.dirname(modulePath);
export const unitNames = Object.freeze([
  "codex-lb-ssh-tunnel.service",
  "codex-lb-model-bridge.service",
]);

function fatal(message) {
  throw new Error(message);
}

const DEFAULT_BRIDGE_PORT = 12455;
const DEFAULT_TUNNEL_PORT = 12456;

function environmentPath(name, fallback) {
  const value = process.env[name];
  return value == null || value === "" ? fallback : value;
}

function environmentPort(name, fallback) {
  const value = process.env[name];
  if (value == null || value === "") return fallback;
  if (!/^\d+$/u.test(value)) fatal(`${name} must be a TCP port number`);
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) fatal(`${name} must be a TCP port number`);
  return port;
}

function defaultCommandRunner(commandName, args, { env = process.env, quiet = false } = {}) {
  return spawnSync(commandName, args, {
    encoding: "utf8",
    env,
    stdio: quiet ? "ignore" : ["ignore", "pipe", "pipe"],
  });
}

export function checkedCommand(runner, commandName, args, options = {}) {
  const result = runner(commandName, args, options);
  if (result?.status !== 0) {
    fatal(`${path.basename(commandName)} failed with status ${result?.status ?? "unknown"}`);
  }
  return `${result.stdout || ""}`;
}

function commandIsSuccessful(runner, commandName, args, options = {}) {
  try {
    return runner(commandName, args, { ...options, quiet: true })?.status === 0;
  } catch {
    return false;
  }
}

function assertAbsoluteDirectory(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) {
    fatal(`${label} must be an absolute path`);
  }
  return path.resolve(value);
}

function assertAbsolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) {
    fatal(`${label} must be an absolute path`);
  }
  return path.resolve(value);
}

function assertIdentityName(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(value)) {
    fatal("sshIdentityName must be a simple file name");
  }
  return value;
}

export function createInstallLayout({
  homeDirectory = os.homedir(),
  configHome = process.env.XDG_CONFIG_HOME || path.join(homeDirectory, ".config"),
  sourceDirectory = defaultSourceDirectory,
  tokenHelper = environmentPath(
    "CODEX_LB_TOKEN_HELPER",
    path.join(homeDirectory, ".local", "libexec", "codex-lb-model-bridge", "provider-token-helper"),
  ),
  codexExecutable = environmentPath("CODEX_EXECUTABLE", path.join(homeDirectory, ".local", "bin", "codex")),
  sshHost = process.env.CODEX_LB_SSH_HOST || null,
  sshUser = process.env.CODEX_LB_SSH_USER || null,
  sshIdentityName = process.env.CODEX_LB_SSH_IDENTITY_NAME || "codex-lb-ssh-key",
  bridgePort = environmentPort("CODEX_LB_BRIDGE_PORT", DEFAULT_BRIDGE_PORT),
  tunnelPort = environmentPort("CODEX_LB_TUNNEL_PORT", DEFAULT_TUNNEL_PORT),
  remotePort = environmentPort("CODEX_LB_REMOTE_PORT", null),
} = {}) {
  const home = assertAbsoluteDirectory(homeDirectory, "homeDirectory");
  const xdgConfig = assertAbsoluteDirectory(configHome, "configHome");
  const source = assertAbsoluteDirectory(sourceDirectory, "sourceDirectory");
  const identityName = assertIdentityName(sshIdentityName);
  return Object.freeze({
    homeDirectory: home,
    configHome: xdgConfig,
    sourceDirectory: source,
    runtimeDirectory: path.join(home, ".local", "libexec", "codex-lb-model-bridge"),
    bridgeConfigDirectory: path.join(xdgConfig, "codex-lb-model-bridge"),
    userUnitDirectory: path.join(xdgConfig, "systemd", "user"),
    codexConfigPath: path.join(home, ".codex", "config.toml"),
    authFile: path.join(home, ".codex", "auth.json"),
    sshIdentity: path.join(home, ".ssh", identityName),
    sshIdentityName: identityName,
    knownHosts: path.join(home, ".ssh", "known_hosts"),
    bridgeConfigPath: path.join(xdgConfig, "codex-lb-model-bridge", "config.json"),
    tokenHelper: assertAbsolutePath(tokenHelper, "tokenHelper"),
    codexExecutable: assertAbsolutePath(codexExecutable, "codexExecutable"),
    sshHost,
    sshUser,
    bridgePort,
    tunnelPort,
    remotePort,
    backupRoot: path.join(home, ".codex", "backups", "codex-lb-model-bridge"),
  });
}

export function installationTargets(layout) {
  return Object.freeze({
    codexConfig: Object.freeze({
      destination: layout.codexConfigPath,
      backupFile: "codex-config.toml",
      installMode: 0o600,
      required: true,
    }),
    runtimeBridge: Object.freeze({
      destination: path.join(layout.runtimeDirectory, "bridge.mjs"),
      backupFile: "runtime-bridge.mjs",
      installMode: 0o555,
    }),
    bridgeConfig: Object.freeze({
      destination: layout.bridgeConfigPath,
      backupFile: "bridge-config.json",
      installMode: 0o600,
    }),
    tunnelUnit: Object.freeze({
      destination: path.join(layout.userUnitDirectory, unitNames[0]),
      backupFile: unitNames[0],
      installMode: 0o644,
    }),
    bridgeUnit: Object.freeze({
      destination: path.join(layout.userUnitDirectory, unitNames[1]),
      backupFile: unitNames[1],
      installMode: 0o644,
    }),
  });
}

function assertPort(value, label) {
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    fatal(`${label} must be a TCP port number`);
  }
  return value;
}

function validateTunnelSettings(layout) {
  if (typeof layout.sshHost !== "string" || net.isIP(layout.sshHost) !== 4) {
    fatal("sshHost must be an IPv4 address supplied for this installation");
  }
  if (typeof layout.sshUser !== "string" || !/^[A-Za-z_][A-Za-z0-9._-]{0,31}$/u.test(layout.sshUser)) {
    fatal("sshUser must be a simple account name supplied for this installation");
  }
  assertPort(layout.tunnelPort, "tunnelPort");
  assertPort(layout.remotePort, "remotePort");
}

function upstreamPort(config, fallback) {
  const candidate = config?.upstream?.port
    ?? (config?.upstreamBaseUrl ? new URL(config.upstreamBaseUrl).port : fallback);
  if (candidate == null || candidate === "") return assertPort(fallback, "tunnelPort");
  return assertPort(Number(candidate), "upstream tunnel port");
}

export function renderTunnelUnit(template, layout, bridgeConfig) {
  if (typeof template !== "string") fatal("SSH tunnel unit template must be text");
  validateTunnelSettings(layout);
  const replacements = new Map([
    ["__CODEX_LB_SSH_IDENTITY__", `%h/.ssh/${layout.sshIdentityName}`],
    ["__CODEX_LB_TUNNEL_PORT__", String(upstreamPort(bridgeConfig, layout.tunnelPort))],
    ["__CODEX_LB_REMOTE_PORT__", String(layout.remotePort)],
    ["__CODEX_LB_SSH_USER__", layout.sshUser],
    ["__CODEX_LB_SSH_HOST__", layout.sshHost],
  ]);
  let rendered = template;
  for (const [marker, value] of replacements) rendered = rendered.replaceAll(marker, value);
  if (/__CODEX_LB_[A-Z_]+__/u.test(rendered)) fatal("SSH tunnel unit has unresolved placeholders");
  return rendered;
}

export function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { mode: 0o700, recursive: true });
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== process.getuid()) {
    fatal(`unsafe directory: ${directory}`);
  }
  fs.chmodSync(directory, 0o700);
}

function ensureDestinationDirectory(directory, privateMode) {
  fs.mkdirSync(directory, { mode: 0o700, recursive: true });
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== process.getuid()) {
    fatal(`unsafe directory: ${directory}`);
  }
  if (privateMode) fs.chmodSync(directory, 0o700);
  else if ((metadata.mode & 0o022) !== 0) fatal(`destination directory is writable by another account: ${directory}`);
}

function assertRegularFile(filePath, {
  label,
  privateMode = false,
  owner = "current-or-root",
  rejectUntrustedWrite = false,
  maximumBytes = 32 * 1024 * 1024,
} = {}) {
  let metadata;
  try {
    metadata = fs.lstatSync(filePath);
  } catch {
    fatal(`required file is unavailable: ${label || filePath}`);
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fatal(`required file is unsafe: ${label || filePath}`);
  }
  if (owner === "current" && metadata.uid !== process.getuid()) {
    fatal(`required file has an unsafe owner: ${label || filePath}`);
  }
  if (owner === "current-or-root" && metadata.uid !== process.getuid() && metadata.uid !== 0) {
    fatal(`required file has an unsafe owner: ${label || filePath}`);
  }
  if (privateMode && (metadata.mode & 0o077) !== 0) {
    fatal(`required file permissions are unsafe: ${label || filePath}`);
  }
  if (!privateMode && (metadata.mode & 0o022) !== 0) {
    fatal(`required file is writable by an untrusted account: ${label || filePath}`);
  }
  if (metadata.size < 1 || metadata.size > maximumBytes) {
    fatal(`required file has an unsafe size: ${label || filePath}`);
  }
  return metadata;
}

function lstatIfPresent(filePath) {
  try {
    return fs.lstatSync(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

function removeTemporary(temporary) {
  try {
    fs.unlinkSync(temporary);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

export function atomicCopy(source, destination, mode) {
  ensureDestinationDirectory(path.dirname(destination), mode === 0o600);
  const temporary = `${destination}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.copyFileSync(source, temporary, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(temporary, mode);
    fs.renameSync(temporary, destination);
  } catch (error) {
    removeTemporary(temporary);
    throw error;
  }
}

export function atomicWrite(destination, content, mode) {
  ensureDestinationDirectory(path.dirname(destination), mode === 0o600);
  const temporary = `${destination}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  try {
    fs.writeFileSync(temporary, content, { encoding: "utf8", flag: "wx", mode });
    fs.chmodSync(temporary, mode);
    fs.renameSync(temporary, destination);
  } catch (error) {
    removeTemporary(temporary);
    throw error;
  }
}

export function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function validateRequiredFiles(layout, runner, env) {
  validateTunnelSettings(layout);
  assertRegularFile(path.join(layout.sourceDirectory, "bridge.mjs"), {
    label: "bridge source",
    owner: "current",
  });
  for (const unitName of unitNames) {
    assertRegularFile(path.join(layout.sourceDirectory, "systemd", unitName), {
      label: unitName,
      owner: "current",
    });
  }
  assertRegularFile(layout.tokenHelper, { label: "provider token helper" });
  assertRegularFile(layout.codexExecutable, {
    label: "Codex executable",
    maximumBytes: 512 * 1024 * 1024,
  });
  assertRegularFile(layout.codexConfigPath, {
    label: "Codex configuration",
    privateMode: true,
    owner: "current",
  });
  assertRegularFile(layout.authFile, {
    label: "Codex authentication",
    privateMode: true,
    owner: "current",
  });
  let authentication;
  try {
    authentication = JSON.parse(fs.readFileSync(layout.authFile, "utf8"));
  } catch {
    fatal("Codex authentication file is invalid JSON");
  }
  if (authentication == null || typeof authentication !== "object"
    || Array.isArray(authentication) || authentication.auth_mode !== "chatgpt") {
    fatal("Codex must be signed in with ChatGPT before installing the bridge");
  }
  assertRegularFile(layout.sshIdentity, {
    label: "SSH identity",
    privateMode: true,
    owner: "current",
  });
  assertRegularFile(layout.knownHosts, {
    label: "SSH known_hosts",
    owner: "current",
    rejectUntrustedWrite: true,
  });
  const pinnedHostKeys = checkedCommand(runner, "/usr/bin/ssh-keygen", [
    "-F",
    layout.sshHost,
    "-f",
    layout.knownHosts,
  ], { env });
  if (!pinnedHostKeys.split("\n").some((line) => /^\S+\s+ssh-ed25519\s+\S+$/u.test(line))) {
    fatal("SSH known_hosts does not contain the required Ed25519 host key");
  }
  checkedCommand(runner, layout.codexExecutable, ["login", "status"], { env, quiet: true });
  checkedCommand(runner, layout.tokenHelper, ["status"], { env, quiet: true });
}

function bridgeConfiguration(layout) {
  if (lstatIfPresent(layout.bridgeConfigPath) != null) {
    assertRegularFile(layout.bridgeConfigPath, {
      label: "existing bridge configuration",
      privateMode: true,
      owner: "current",
      maximumBytes: 128 * 1024,
    });
    return normalizeConfig(JSON.parse(fs.readFileSync(layout.bridgeConfigPath, "utf8")));
  }
  return normalizeConfig({
    version: 1,
    listenHost: "127.0.0.1",
    listenPort: layout.bridgePort,
    publicBasePath: `/${crypto.randomBytes(32).toString("hex")}/backend-api/codex`,
    upstreamBaseUrl: `http://127.0.0.1:${layout.tunnelPort}/backend-api/codex`,
    authFile: layout.authFile,
    providerTokenHelper: layout.tokenHelper,
    providerTokenPrefix: "sk-clb-",
    actorAuthorization: "codex-lb",
    tokenTimeoutMs: 5_000,
    connectTimeoutMs: 10_000,
    idleTimeoutMs: 60 * 60 * 1000,
    maxConnections: 32,
    maxRequestBytes: 256 * 1024 * 1024,
    maxResponseBytes: 256 * 1024 * 1024,
  });
}

function serializableBridgeConfig(config) {
  const { upstream, ...plain } = config;
  return { ...plain, upstreamBaseUrl: upstream.href.replace(/\/$/u, "") };
}

function replaceKeyInRange(lines, start, end, key, value) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const matcher = new RegExp(`^\\s*${escaped}\\s*=`, "u");
  const matches = [];
  for (let index = start; index < end; index += 1) {
    if (matcher.test(lines[index])) matches.push(index);
  }
  if (matches.length > 1) fatal(`duplicate TOML key: ${key}`);
  const replacement = `${key} = ${JSON.stringify(value)}`;
  if (matches.length === 1) {
    lines[matches[0]] = replacement;
    return;
  }
  lines.splice(start, 0, replacement);
}

function setTopLevelKey(text, key, value) {
  const lines = text.split("\n");
  const firstSection = lines.findIndex((line) => /^\s*\[/u.test(line));
  replaceKeyInRange(lines, 0, firstSection < 0 ? lines.length : firstSection, key, value);
  return lines.join("\n");
}

function removeTopLevelKey(text, key) {
  const lines = text.split("\n");
  const firstSection = lines.findIndex((line) => /^\s*\[/u.test(line));
  const end = firstSection < 0 ? lines.length : firstSection;
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const matcher = new RegExp(`^\\s*${escaped}\\s*=`, "u");
  const matches = [];
  for (let index = 0; index < end; index += 1) {
    if (matcher.test(lines[index])) matches.push(index);
  }
  if (matches.length > 1) fatal(`duplicate TOML key: ${key}`);
  if (matches.length === 1) lines.splice(matches[0], 1);
  return lines.join("\n");
}

export function configuredCodexToml(original, config) {
  let updated = original;
  updated = removeTopLevelKey(updated, "service_tier");
  updated = setTopLevelKey(updated, "model_provider", "openai");
  updated = setTopLevelKey(
    updated,
    "openai_base_url",
    `http://127.0.0.1:${config.listenPort}${config.publicBasePath}`,
  );
  return updated;
}

function snapshotTarget(backupDirectory, target) {
  if (lstatIfPresent(target.destination) == null) return { existed: false };
  const metadata = assertRegularFile(target.destination, {
    label: target.destination,
    owner: "current",
    privateMode: target.installMode === 0o600,
    rejectUntrustedWrite: target.installMode !== 0o600,
  });
  const backupPath = path.join(backupDirectory, "files", target.backupFile);
  atomicCopy(target.destination, backupPath, 0o600);
  return {
    existed: true,
    mode: metadata.mode & 0o777,
    sha256: sha256File(backupPath),
  };
}

export function makeBackup(layout, runner, env) {
  ensurePrivateDirectory(layout.backupRoot);
  const timestamp = new Date().toISOString().replace(/[-:.]/gu, "");
  const directory = path.join(layout.backupRoot, `${timestamp}-${crypto.randomBytes(3).toString("hex")}`);
  ensurePrivateDirectory(directory);
  ensurePrivateDirectory(path.join(directory, "files"));
  const targets = installationTargets(layout);
  const snapshots = {};
  for (const [identifier, target] of Object.entries(targets)) {
    snapshots[identifier] = snapshotTarget(directory, target);
  }
  const manifest = {
    version: 1,
    createdAt: new Date().toISOString(),
    bridgeSourceSha256: sha256File(path.join(layout.sourceDirectory, "bridge.mjs")),
    targets: snapshots,
    services: Object.fromEntries(unitNames.map((name) => [name, {
      active: commandIsSuccessful(runner, "/usr/bin/systemctl", ["--user", "is-active", "--quiet", name], { env }),
      enabled: commandIsSuccessful(runner, "/usr/bin/systemctl", ["--user", "is-enabled", "--quiet", name], { env }),
    }])),
  };
  atomicWrite(path.join(directory, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, 0o600);
  return { directory, manifest };
}

function removeInstalledTarget(targetPath) {
  try {
    const metadata = fs.lstatSync(targetPath);
    if (!metadata.isFile() && !metadata.isSymbolicLink()) fatal(`refusing to remove non-file target: ${targetPath}`);
    fs.unlinkSync(targetPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

export function validateBackupSnapshots(layout, backupDirectory, manifest) {
  if (manifest?.version !== 1 || manifest.targets == null || typeof manifest.targets !== "object") {
    fatal("invalid backup manifest");
  }
  const targets = installationTargets(layout);
  for (const [identifier, target] of Object.entries(targets)) {
    const snapshot = manifest.targets[identifier];
    if (snapshot == null || typeof snapshot !== "object" || typeof snapshot.existed !== "boolean") {
      fatal(`invalid backup target: ${identifier}`);
    }
    if (!snapshot.existed) continue;
    if (!Number.isInteger(snapshot.mode) || snapshot.mode < 0 || snapshot.mode > 0o777
      || !/^[a-f0-9]{64}$/u.test(snapshot.sha256 || "")) {
      fatal(`invalid backup metadata: ${identifier}`);
    }
    const source = path.join(backupDirectory, "files", target.backupFile);
    assertRegularFile(source, {
      label: `backup ${identifier}`,
      privateMode: true,
      owner: "current",
    });
    if (sha256File(source) !== snapshot.sha256) fatal(`backup checksum mismatch: ${identifier}`);
  }
  if (manifest.services == null || typeof manifest.services !== "object") fatal("invalid backup service state");
  for (const name of unitNames) {
    const state = manifest.services[name];
    if (state == null || typeof state.active !== "boolean" || typeof state.enabled !== "boolean") {
      fatal(`invalid backup service state: ${name}`);
    }
  }
}

export function restoreFiles(layout, backupDirectory, manifest) {
  validateBackupSnapshots(layout, backupDirectory, manifest);
  for (const [identifier, target] of Object.entries(installationTargets(layout))) {
    const snapshot = manifest.targets[identifier];
    if (snapshot.existed) {
      atomicCopy(path.join(backupDirectory, "files", target.backupFile), target.destination, snapshot.mode);
    } else {
      removeInstalledTarget(target.destination);
    }
  }
}

export function restoreServiceStateStrict(runner, services, env) {
  for (const name of unitNames) {
    if (services[name].enabled) {
      checkedCommand(runner, "/usr/bin/systemctl", ["--user", "enable", name], { env });
    }
  }
  for (const name of unitNames) {
    if (services[name].active) {
      checkedCommand(runner, "/usr/bin/systemctl", ["--user", "start", name], { env });
    }
  }
}

function bestEffortRestore(layout, backup, runner, env, { managerReloadAttempted, servicesTouched }) {
  const failures = [];
  const attempt = (operation) => {
    try {
      operation();
    } catch (error) {
      failures.push(error);
    }
  };
  if (servicesTouched) {
    attempt(() => checkedCommand(
      runner,
      "/usr/bin/systemctl",
      ["--user", "disable", "--now", ...[...unitNames].reverse()],
      { env, quiet: true },
    ));
  }
  attempt(() => restoreFiles(layout, backup.directory, backup.manifest));
  if (managerReloadAttempted) {
    attempt(() => checkedCommand(runner, "/usr/bin/systemctl", ["--user", "daemon-reload"], { env, quiet: true }));
  }
  if (servicesTouched) {
    attempt(() => restoreServiceStateStrict(runner, backup.manifest.services, env));
  }
  return failures;
}

export function waitForPort(port, timeoutMs = 10_000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const socket = net.createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() - started >= timeoutMs) reject(new Error(`local port ${port} did not become ready`));
        else setTimeout(tryConnect, 100);
      });
    };
    tryConnect();
  });
}

export async function installCompanion({
  layout = createInstallLayout(),
  commandRunner = defaultCommandRunner,
  portWaiter = waitForPort,
  env = process.env,
} = {}) {
  validateRequiredFiles(layout, commandRunner, env);
  const bridgeConfig = bridgeConfiguration(layout);
  const originalConfig = fs.readFileSync(layout.codexConfigPath, "utf8");
  const updatedConfig = configuredCodexToml(originalConfig, bridgeConfig);
  const backup = makeBackup(layout, commandRunner, env);
  const originalDigest = crypto.createHash("sha256").update(originalConfig).digest("hex");
  if (backup.manifest.targets.codexConfig.sha256 !== originalDigest) {
    fatal("Codex configuration changed during installation preflight");
  }
  let managerReloadAttempted = false;
  let servicesTouched = false;
  try {
    const targets = installationTargets(layout);
    atomicCopy(path.join(layout.sourceDirectory, "bridge.mjs"), targets.runtimeBridge.destination, targets.runtimeBridge.installMode);
    atomicWrite(
      targets.bridgeConfig.destination,
      `${JSON.stringify(serializableBridgeConfig(bridgeConfig), null, 2)}\n`,
      targets.bridgeConfig.installMode,
    );
    for (const [index, unitName] of unitNames.entries()) {
      const target = index === 0 ? targets.tunnelUnit : targets.bridgeUnit;
      const sourcePath = path.join(layout.sourceDirectory, "systemd", unitName);
      if (index === 0) {
        atomicWrite(
          target.destination,
          renderTunnelUnit(fs.readFileSync(sourcePath, "utf8"), layout, bridgeConfig),
          target.installMode,
        );
      } else {
        atomicCopy(sourcePath, target.destination, target.installMode);
      }
    }
    checkedCommand(commandRunner, "/usr/bin/systemd-analyze", [
      "--user",
      "verify",
      ...unitNames.map((name) => path.join(layout.userUnitDirectory, name)),
    ], { env });
    managerReloadAttempted = true;
    checkedCommand(commandRunner, "/usr/bin/systemctl", ["--user", "daemon-reload"], { env });
    servicesTouched = true;
    checkedCommand(commandRunner, "/usr/bin/systemctl", ["--user", "enable", ...unitNames], { env });
    checkedCommand(commandRunner, "/usr/bin/systemctl", ["--user", "restart", unitNames[0]], { env });
    await portWaiter(Number(bridgeConfig.upstream.port));
    checkedCommand(commandRunner, "/usr/bin/systemctl", ["--user", "restart", unitNames[1]], { env });
    await portWaiter(bridgeConfig.listenPort);
    for (const unitName of unitNames) {
      checkedCommand(commandRunner, "/usr/bin/systemctl", ["--user", "is-active", "--quiet", unitName], { env });
    }

    atomicWrite(layout.codexConfigPath, updatedConfig, 0o600);
    // `features` and `login` reject the global --strict-config flag in the
    // current desktop CLI. A stdio app-server with closed stdin performs the
    // strict parse and then exits cleanly without creating a task.
    checkedCommand(commandRunner, layout.codexExecutable, ["app-server", "--strict-config", "--stdio"], { env, quiet: true });
    return {
      success: true,
      backupDirectory: backup.directory,
      bridgeActive: true,
      encryptedTunnelActive: true,
      desktopRestartRequired: true,
    };
  } catch (error) {
    const rollbackFailures = bestEffortRestore(layout, backup, commandRunner, env, {
      managerReloadAttempted,
      servicesTouched,
    });
    if (rollbackFailures.length > 0) {
      throw new Error(`installation failed and automatic rollback reported ${rollbackFailures.length} error(s)`, { cause: error });
    }
    throw error;
  }
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "--install") {
    fatal("usage: install.mjs --install");
  }
  const result = await installCompanion();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({ success: false, error: error.message })}\n`);
    process.exit(1);
  });
}
