#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  checkedCommand,
  createInstallLayout,
  restoreFiles,
  restoreServiceStateStrict,
  unitNames,
  validateBackupSnapshots,
} from "./install.mjs";

const modulePath = fileURLToPath(import.meta.url);
const MAX_MANIFEST_BYTES = 256 * 1024;

function fatal(message) {
  throw new Error(message);
}

function defaultCommandRunner(commandName, args, { env = process.env, quiet = false } = {}) {
  return spawnSync(commandName, args, {
    encoding: "utf8",
    env,
    stdio: quiet ? "ignore" : ["ignore", "pipe", "pipe"],
  });
}

function assertPrivateDirectory(directory, label) {
  const metadata = fs.lstatSync(directory);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid !== process.getuid()
    || (metadata.mode & 0o077) !== 0) {
    fatal(`${label} is unsafe`);
  }
}

function readManifest(manifestPath) {
  const metadata = fs.lstatSync(manifestPath);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1
    || metadata.uid !== process.getuid() || (metadata.mode & 0o077) !== 0
    || metadata.size < 2 || metadata.size > MAX_MANIFEST_BYTES) {
    fatal("backup manifest is unsafe");
  }
  try {
    return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    fatal("backup manifest is invalid JSON");
  }
}

export function loadBackup(layout, requestedDirectory) {
  if (typeof requestedDirectory !== "string" || !path.isAbsolute(requestedDirectory)
    || requestedDirectory.includes("\0")) {
    fatal("invalid backup directory");
  }
  assertPrivateDirectory(layout.backupRoot, "backup root");
  const root = fs.realpathSync(layout.backupRoot);
  const requestedPath = path.resolve(requestedDirectory);
  const requestedMetadata = fs.lstatSync(requestedPath);
  if (!requestedMetadata.isDirectory() || requestedMetadata.isSymbolicLink()) {
    fatal("backup directory is unsafe");
  }
  const backupDirectory = fs.realpathSync(requestedPath);
  if (!backupDirectory.startsWith(`${root}${path.sep}`)) {
    fatal("backup directory is outside the allowed root");
  }
  assertPrivateDirectory(backupDirectory, "backup directory");
  assertPrivateDirectory(path.join(backupDirectory, "files"), "backup files directory");
  const manifest = readManifest(path.join(backupDirectory, "manifest.json"));
  validateBackupSnapshots(layout, backupDirectory, manifest);
  return { directory: backupDirectory, manifest };
}

export function rollbackCompanion({
  backupDirectory,
  layout = createInstallLayout({ homeDirectory: os.homedir() }),
  commandRunner = defaultCommandRunner,
  env = process.env,
} = {}) {
  const backup = loadBackup(layout, backupDirectory);
  checkedCommand(
    commandRunner,
    "/usr/bin/systemctl",
    ["--user", "disable", "--now", ...[...unitNames].reverse()],
    { env },
  );
  restoreFiles(layout, backup.directory, backup.manifest);
  checkedCommand(commandRunner, "/usr/bin/systemctl", ["--user", "daemon-reload"], { env });
  restoreServiceStateStrict(commandRunner, backup.manifest.services, env);
  return {
    success: true,
    configRestored: true,
    installationFilesRestored: true,
    serviceStateRestored: true,
    desktopRestartRequired: true,
  };
}

function main() {
  if (process.argv.length !== 4 || process.argv[2] !== "--backup") {
    fatal("usage: rollback.mjs --backup BACKUP_DIRECTORY");
  }
  const result = rollbackCompanion({ backupDirectory: process.argv[3] });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ success: false, error: error.message })}\n`);
    process.exit(1);
  }
}
