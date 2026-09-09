import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  checkedCommand,
  configuredCodexToml,
  createInstallLayout,
  installCompanion,
  installationTargets,
  renderTunnelUnit,
  unitNames,
} from "../install.mjs";
import { loadBackup, rollbackCompanion } from "../rollback.mjs";

const sourceDirectory = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function writeFixtureFile(filePath, content, mode) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, content, { mode });
  fs.chmodSync(filePath, mode);
}

function validBridgeConfig(layout, character = "b") {
  return {
    version: 1,
    listenHost: "127.0.0.1",
    listenPort: layout.bridgePort,
    publicBasePath: `/${character.repeat(64)}/backend-api/codex`,
    upstreamBaseUrl: `http://127.0.0.1:${layout.tunnelPort}/backend-api/codex`,
    authFile: layout.authFile,
    providerTokenHelper: layout.tokenHelper,
    providerTokenPrefix: "synthetic-provider-",
    actorAuthorization: "codex-lb",
    tokenTimeoutMs: 5_000,
    connectTimeoutMs: 10_000,
    idleTimeoutMs: 3_600_000,
    maxConnections: 32,
    maxRequestBytes: 256 * 1024 * 1024,
    maxResponseBytes: 256 * 1024 * 1024,
  };
}

function makeFixture(t, { preexistingInstallation = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "codex-lb-installer-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const homeDirectory = path.join(root, "home");
  const configHome = path.join(root, "xdg-config");
  const tokenHelper = path.join(root, "dependencies", "codex-lb-keyring.py");
  const codexExecutable = path.join(root, "dependencies", "codex");
  const layout = createInstallLayout({
    homeDirectory,
    configHome,
    sourceDirectory,
    tokenHelper,
    codexExecutable,
    sshHost: "198.51.100.10",
    sshUser: "bridge",
    remotePort: 9443,
  });
  const originalCodexConfig = [
    "# isolated fixture",
    'model_provider = "legacy-provider"',
    'openai_base_url = "http://legacy.invalid"',
    'service_tier = "priority"',
    "",
    "[[projects]]",
    'name = "fixture"',
    "",
    "[model_providers.codex-lb]",
    'base_url = "http://legacy-lb.invalid/backend-api/codex"',
    "",
    "[model_providers.codex_lb]",
    'base_url = "http://legacy-lb.invalid/v1"',
    "",
  ].join("\n");
  writeFixtureFile(layout.codexConfigPath, originalCodexConfig, 0o600);
  writeFixtureFile(layout.authFile, '{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic"}}\n', 0o600);
  writeFixtureFile(layout.sshIdentity, "synthetic-private-key\n", 0o600);
  writeFixtureFile(layout.knownHosts, "198.51.100.10 ssh-ed25519 synthetic-host-key\n", 0o600);
  writeFixtureFile(tokenHelper, "#!/usr/bin/env python3\n", 0o700);
  writeFixtureFile(codexExecutable, "#!/bin/sh\nexit 0\n", 0o700);
  fs.mkdirSync(layout.userUnitDirectory, { recursive: true, mode: 0o755 });
  fs.chmodSync(layout.userUnitDirectory, 0o755);

  const oldTargets = {};
  if (preexistingInstallation) {
    const targets = installationTargets(layout);
    oldTargets.runtimeBridge = "// previous runtime bridge\n";
    oldTargets.bridgeConfig = `${JSON.stringify(validBridgeConfig(layout), null, 2)}\n`;
    oldTargets.tunnelUnit = "# previous tunnel unit\n";
    oldTargets.bridgeUnit = "# previous bridge unit\n";
    writeFixtureFile(targets.runtimeBridge.destination, oldTargets.runtimeBridge, 0o555);
    writeFixtureFile(targets.bridgeConfig.destination, oldTargets.bridgeConfig, 0o600);
    writeFixtureFile(targets.tunnelUnit.destination, oldTargets.tunnelUnit, 0o644);
    writeFixtureFile(targets.bridgeUnit.destination, oldTargets.bridgeUnit, 0o644);
  }
  return {
    root,
    layout,
    originalCodexConfig,
    oldTargets,
    env: {
      HOME: homeDirectory,
      XDG_CONFIG_HOME: configHome,
      XDG_RUNTIME_DIR: path.join(root, "runtime"),
    },
  };
}

function cloneStates(states) {
  return Object.fromEntries(Object.entries(states).map(([name, state]) => [name, { ...state }]));
}

function makeRunner({ initialStates, shouldFail } = {}) {
  const states = cloneStates(initialStates ?? Object.fromEntries(
    unitNames.map((name) => [name, { active: false, enabled: false }]),
  ));
  const calls = [];
  const runner = (commandName, args, options = {}) => {
    const call = { commandName, args: [...args], options: { ...options } };
    calls.push(call);
    if (shouldFail?.(call, calls.length)) {
      return { status: 1, stdout: "", stderr: "synthetic-stderr-secret" };
    }
    if (commandName === "/usr/bin/ssh-keygen") {
      return { status: 0, stdout: "198.51.100.10 ssh-ed25519 synthetic-host-key\n", stderr: "" };
    }
    if (commandName !== "/usr/bin/systemctl") return { status: 0, stdout: "", stderr: "" };
    const operation = args[1];
    if (operation === "is-active") {
      const name = args.at(-1);
      return { status: states[name]?.active ? 0 : 3, stdout: "", stderr: "" };
    }
    if (operation === "is-enabled") {
      const name = args.at(-1);
      return { status: states[name]?.enabled ? 0 : 1, stdout: "", stderr: "" };
    }
    if (operation === "daemon-reload") return { status: 0, stdout: "", stderr: "" };
    if (operation === "enable") {
      for (const name of args.slice(2)) states[name].enabled = true;
      return { status: 0, stdout: "", stderr: "" };
    }
    if (operation === "disable") {
      const stopNow = args.includes("--now");
      for (const name of args.slice(2).filter((entry) => entry !== "--now")) {
        states[name].enabled = false;
        if (stopNow) states[name].active = false;
      }
      return { status: 0, stdout: "", stderr: "" };
    }
    if (operation === "restart" || operation === "start") {
      states[args.at(-1)].active = true;
      return { status: 0, stdout: "", stderr: "" };
    }
    if (operation === "stop") {
      states[args.at(-1)].active = false;
      return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`unhandled fake systemctl invocation: ${args.join(" ")}`);
  };
  return { calls, runner, states };
}

function fileMode(filePath) {
  return fs.statSync(filePath).mode & 0o777;
}

test("systemd user unit templates render and pass systemd-analyze verify", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "codex-lb-unit-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const layout = createInstallLayout({
    homeDirectory: path.join(root, "home"),
    configHome: path.join(root, "config"),
    sourceDirectory,
    tokenHelper: path.join(root, "provider-token-helper"),
    codexExecutable: path.join(root, "codex"),
    sshHost: "198.51.100.10",
    sshUser: "bridge",
    remotePort: 9443,
  });
  const renderedTunnel = renderTunnelUnit(
    fs.readFileSync(path.join(sourceDirectory, "systemd", unitNames[0]), "utf8"),
    layout,
    { upstreamBaseUrl: `http://127.0.0.1:${layout.tunnelPort}/backend-api/codex` },
  );
  assert.doesNotMatch(renderedTunnel, /__CODEX_LB_/u);
  assert.match(renderedTunnel, /bridge@198\.51\.100\.10/u);
  assert.match(renderedTunnel, /127\.0\.0\.1:12456:127\.0\.0\.1:9443/u);
  const renderedTunnelPath = path.join(root, unitNames[0]);
  fs.writeFileSync(renderedTunnelPath, renderedTunnel);
  const units = [renderedTunnelPath, path.join(sourceDirectory, "systemd", unitNames[1])];
  const result = spawnSync("/usr/bin/systemd-analyze", ["--user", "verify", ...units], {
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: "/nonexistent/codex-lb-unit-verification",
      XDG_CONFIG_HOME: "/nonexistent/codex-lb-unit-verification/config",
    },
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});

test("systemd user units avoid optional capability operations", () => {
  const unsupported = /^(?:AmbientCapabilities|CapabilityBoundingSet|PrivateDevices|ProtectClock|ProtectKernelLogs|ProtectKernelModules)=/mu;
  for (const unitName of unitNames) {
    const unit = fs.readFileSync(path.join(sourceDirectory, "systemd", unitName), "utf8");
    assert.doesNotMatch(unit, unsupported);
  }
});

test("install and rollback complete inside isolated HOME and XDG_CONFIG_HOME", async (t) => {
  const fixture = makeFixture(t);
  const fake = makeRunner();
  const waitedPorts = [];
  const installResult = await installCompanion({
    layout: fixture.layout,
    commandRunner: fake.runner,
    portWaiter: async (port) => { waitedPorts.push(port); },
    env: fixture.env,
  });
  assert.equal(installResult.success, true);
  assert.deepEqual(waitedPorts, [fixture.layout.tunnelPort, fixture.layout.bridgePort]);
  assert.ok(installResult.backupDirectory.startsWith(`${fixture.layout.backupRoot}${path.sep}`));
  assert.equal(fs.existsSync(path.join(fixture.layout.homeDirectory, ".config")), false);

  const targets = installationTargets(fixture.layout);
  assert.equal(fileMode(targets.runtimeBridge.destination), 0o555);
  assert.equal(fileMode(targets.bridgeConfig.destination), 0o600);
  assert.equal(fileMode(targets.tunnelUnit.destination), 0o644);
  assert.equal(fileMode(targets.bridgeUnit.destination), 0o644);
  assert.equal(fileMode(fixture.layout.userUnitDirectory), 0o755);
  const bridgeConfig = JSON.parse(fs.readFileSync(targets.bridgeConfig.destination, "utf8"));
  assert.match(bridgeConfig.publicBasePath, /^\/[a-f0-9]{64}\/backend-api\/codex$/u);
  assert.equal(bridgeConfig.authFile, fixture.layout.authFile);
  assert.equal(bridgeConfig.providerTokenHelper, fixture.layout.tokenHelper);
  const installedTunnelUnit = fs.readFileSync(targets.tunnelUnit.destination, "utf8");
  assert.doesNotMatch(installedTunnelUnit, /__CODEX_LB_/u);
  assert.match(installedTunnelUnit, /bridge@198\.51\.100\.10/u);
  assert.match(installedTunnelUnit, /127\.0\.0\.1:12456:127\.0\.0\.1:9443/u);

  const installedCodexConfig = fs.readFileSync(fixture.layout.codexConfigPath, "utf8");
  assert.match(installedCodexConfig, /^model_provider = "openai"$/mu);
  assert.doesNotMatch(installedCodexConfig, /^service_tier\s*=/mu);
  assert.match(
    installedCodexConfig,
    new RegExp(`^openai_base_url = ${JSON.stringify(`http://127.0.0.1:12455${bridgeConfig.publicBasePath}`)}$`, "mu"),
  );
  assert.match(installedCodexConfig, /^base_url = "http:\/\/legacy-lb\.invalid\/backend-api\/codex"$/mu);
  assert.match(installedCodexConfig, /^base_url = "http:\/\/legacy-lb\.invalid\/v1"$/mu);
  assert.ok(installedCodexConfig.indexOf("model_provider") < installedCodexConfig.indexOf("[[projects]]"));
  assert.deepEqual(fake.states, Object.fromEntries(
    unitNames.map((name) => [name, { active: true, enabled: true }]),
  ));

  const verifyCall = fake.calls.find((call) => call.commandName === "/usr/bin/systemd-analyze");
  assert.deepEqual(verifyCall.args, [
    "--user",
    "verify",
    path.join(fixture.layout.userUnitDirectory, unitNames[0]),
    path.join(fixture.layout.userUnitDirectory, unitNames[1]),
  ]);
  for (const call of fake.calls) {
    assert.notEqual(call.commandName, "/bin/systemctl");
  }

  const rollbackResult = rollbackCompanion({
    backupDirectory: installResult.backupDirectory,
    layout: fixture.layout,
    commandRunner: fake.runner,
    env: fixture.env,
  });
  assert.equal(rollbackResult.success, true);
  assert.equal(fs.readFileSync(fixture.layout.codexConfigPath, "utf8"), fixture.originalCodexConfig);
  for (const target of Object.values(targets).filter((target) => !target.required)) {
    assert.equal(fs.existsSync(target.destination), false, target.destination);
  }
  assert.deepEqual(fake.states, Object.fromEntries(
    unitNames.map((name) => [name, { active: false, enabled: false }]),
  ));
});

test("rollback restores a previous installation and its mixed service state", async (t) => {
  const fixture = makeFixture(t, { preexistingInstallation: true });
  const initialStates = {
    [unitNames[0]]: { active: true, enabled: true },
    [unitNames[1]]: { active: true, enabled: false },
  };
  const fake = makeRunner({ initialStates });
  const installResult = await installCompanion({
    layout: fixture.layout,
    commandRunner: fake.runner,
    portWaiter: async () => {},
    env: fixture.env,
  });
  rollbackCompanion({
    backupDirectory: installResult.backupDirectory,
    layout: fixture.layout,
    commandRunner: fake.runner,
    env: fixture.env,
  });

  const targets = installationTargets(fixture.layout);
  assert.equal(fs.readFileSync(fixture.layout.codexConfigPath, "utf8"), fixture.originalCodexConfig);
  assert.equal(fs.readFileSync(targets.runtimeBridge.destination, "utf8"), fixture.oldTargets.runtimeBridge);
  assert.equal(fs.readFileSync(targets.bridgeConfig.destination, "utf8"), fixture.oldTargets.bridgeConfig);
  assert.equal(fs.readFileSync(targets.tunnelUnit.destination, "utf8"), fixture.oldTargets.tunnelUnit);
  assert.equal(fs.readFileSync(targets.bridgeUnit.destination, "utf8"), fixture.oldTargets.bridgeUnit);
  assert.equal(fileMode(targets.runtimeBridge.destination), 0o555);
  assert.equal(fileMode(targets.bridgeConfig.destination), 0o600);
  assert.equal(fileMode(targets.tunnelUnit.destination), 0o644);
  assert.equal(fileMode(targets.bridgeUnit.destination), 0o644);
  assert.deepEqual(fake.states, initialStates);
});

test("a late installation failure automatically restores every file and service state", async (t) => {
  const fixture = makeFixture(t, { preexistingInstallation: true });
  const initialStates = {
    [unitNames[0]]: { active: false, enabled: true },
    [unitNames[1]]: { active: true, enabled: false },
  };
  let strictValidationFailed = false;
  const fake = makeRunner({
    initialStates,
    shouldFail: (call) => {
      if (call.commandName === fixture.layout.codexExecutable
        && call.args.join(" ") === "app-server --strict-config --stdio"
        && !strictValidationFailed) {
        strictValidationFailed = true;
        return true;
      }
      return false;
    },
  });
  await assert.rejects(
    installCompanion({
      layout: fixture.layout,
      commandRunner: fake.runner,
      portWaiter: async () => {},
      env: fixture.env,
    }),
    (error) => {
      assert.match(error.message, /codex failed with status 1/u);
      assert.doesNotMatch(error.message, /synthetic-stderr-secret/u);
      return true;
    },
  );
  const targets = installationTargets(fixture.layout);
  assert.equal(fs.readFileSync(fixture.layout.codexConfigPath, "utf8"), fixture.originalCodexConfig);
  assert.equal(fs.readFileSync(targets.runtimeBridge.destination, "utf8"), fixture.oldTargets.runtimeBridge);
  assert.equal(fs.readFileSync(targets.bridgeConfig.destination, "utf8"), fixture.oldTargets.bridgeConfig);
  assert.equal(fs.readFileSync(targets.tunnelUnit.destination, "utf8"), fixture.oldTargets.tunnelUnit);
  assert.equal(fs.readFileSync(targets.bridgeUnit.destination, "utf8"), fixture.oldTargets.bridgeUnit);
  assert.deepEqual(fake.states, initialStates);
});

test("tampered or out-of-root backups fail before service mutation", async (t) => {
  const fixture = makeFixture(t);
  const fake = makeRunner();
  const installResult = await installCompanion({
    layout: fixture.layout,
    commandRunner: fake.runner,
    portWaiter: async () => {},
    env: fixture.env,
  });
  const backup = loadBackup(fixture.layout, installResult.backupDirectory);
  const backedUpConfig = path.join(backup.directory, "files", "codex-config.toml");
  fs.appendFileSync(backedUpConfig, "tampered\n");
  const callsBefore = fake.calls.length;
  assert.throws(
    () => rollbackCompanion({
      backupDirectory: installResult.backupDirectory,
      layout: fixture.layout,
      commandRunner: fake.runner,
      env: fixture.env,
    }),
    /backup checksum mismatch/u,
  );
  assert.equal(fake.calls.length, callsBefore);

  const outside = path.join(fixture.root, "outside-backup");
  fs.mkdirSync(path.join(outside, "files"), { recursive: true, mode: 0o700 });
  fs.chmodSync(outside, 0o700);
  assert.throws(() => loadBackup(fixture.layout, outside), /outside the allowed root/u);
});

test("TOML editing treats an array table as the end of top-level keys", () => {
  const config = {
    listenPort: 12455,
    publicBasePath: `/${"c".repeat(64)}/backend-api/codex`,
  };
  const input = '# comment\n[[projects]]\nname = "first"\n';
  const output = configuredCodexToml(input, config);
  assert.ok(output.indexOf("model_provider") < output.indexOf("[[projects]]"));
  assert.ok(output.indexOf("openai_base_url") < output.indexOf("[[projects]]"));
});

test("TOML editing leaves legacy provider sections byte-for-byte unchanged", () => {
  const config = {
    listenPort: 12455,
    publicBasePath: `/${"d".repeat(64)}/backend-api/codex`,
  };
  const sections = [
    "[model_providers.codex-lb]",
    'base_url = "http://legacy-lb.invalid/backend-api/codex"',
    'service_tier = "priority"',
    "custom = true",
    "",
    "[model_providers.codex_lb]",
    'base_url = "http://legacy-lb.invalid/v1"',
    "custom = false",
    "",
  ].join("\n");
  const output = configuredCodexToml(sections, config);
  assert.ok(output.endsWith(sections));
});

test("TOML editing removes only the global service tier", () => {
  const config = {
    listenPort: 12455,
    publicBasePath: `/${"e".repeat(64)}/backend-api/codex`,
  };
  const input = [
    'service_tier = "priority"',
    "",
    "[profiles.fast]",
    'service_tier = "flex"',
    "",
  ].join("\n");
  const output = configuredCodexToml(input, config);
  assert.doesNotMatch(output, /^service_tier\s*=/u);
  assert.match(output, /^\[profiles\.fast\]\nservice_tier = "flex"$/mu);
});

test("preflight rejects non-ChatGPT authentication before external commands or writes", async (t) => {
  const fixture = makeFixture(t);
  writeFixtureFile(fixture.layout.authFile, '{"auth_mode":"apikey"}\n', 0o600);
  const fake = makeRunner();
  await assert.rejects(
    installCompanion({
      layout: fixture.layout,
      commandRunner: fake.runner,
      portWaiter: async () => {},
      env: fixture.env,
    }),
    /must be signed in with ChatGPT/u,
  );
  assert.equal(fake.calls.length, 0);
  assert.equal(fs.existsSync(fixture.layout.backupRoot), false);
});

test("preflight rejects a host pin that is not Ed25519 before any backup or service change", async (t) => {
  const fixture = makeFixture(t);
  const fake = makeRunner();
  const runner = (commandName, args, options) => {
    if (commandName === "/usr/bin/ssh-keygen") {
      return { status: 0, stdout: "198.51.100.10 ssh-rsa synthetic-host-key\n", stderr: "" };
    }
    return fake.runner(commandName, args, options);
  };
  await assert.rejects(
    installCompanion({
      layout: fixture.layout,
      commandRunner: runner,
      portWaiter: async () => {},
      env: fixture.env,
    }),
    /required Ed25519 host key/u,
  );
  assert.equal(fs.existsSync(fixture.layout.backupRoot), false);
  assert.deepEqual(fake.states, Object.fromEntries(
    unitNames.map((name) => [name, { active: false, enabled: false }]),
  ));
});

test("checked command failures never copy command stderr into installer errors", () => {
  const secret = "stderr-contained-secret";
  assert.throws(
    () => checkedCommand(
      () => ({ status: 7, stdout: "", stderr: secret }),
      "/synthetic/command",
      ["status"],
    ),
    (error) => {
      assert.match(error.message, /command failed with status 7/u);
      assert.equal(error.message.includes(secret), false);
      return true;
    },
  );
});
