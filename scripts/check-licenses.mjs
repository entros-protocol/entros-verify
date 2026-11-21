#!/usr/bin/env node
/**
 * Permissive runtime dependency license gate.
 *
 * Verifies that `@entros/verify` and every resolved runtime dependency package
 * use strictly permissive SPDX licenses (MIT, Apache-2.0, BSD-2-Clause,
 * BSD-3-Clause, ISC) with zero GPL, AGPL, LGPL, or unknown licenses.
 *
 * Usage:
 *   node scripts/check-licenses.mjs               # Audit lockfile + installed runtime node_modules
 *   node scripts/check-licenses.mjs --clean-room  # Also run fresh `npm ci --omit=dev --ignore-scripts`
 */

import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ALLOWED_SPDX_LICENSES = Object.freeze([
  "MIT",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
]);

const ALLOWED_SET = new Set(ALLOWED_SPDX_LICENSES);
const COPYLEFT_TOKEN_PATTERN = /(^|[^A-Za-z0-9])(A|L)?GPL([^A-Za-z0-9]|$)/i;
const COPYLEFT_TEXT_PATTERNS = [
  /GNU\s+GENERAL\s+PUBLIC\s+LICENSE/i,
  /GNU\s+AFFERO\s+GENERAL\s+PUBLIC\s+LICENSE/i,
  /GNU\s+LESSER\s+GENERAL\s+PUBLIC\s+LICENSE/i,
  /GNU\s+LIBRARY\s+GENERAL\s+PUBLIC\s+LICENSE/i,
];

function tokenizeSpdx(expression) {
  const tokens = [];
  let index = 0;
  while (index < expression.length) {
    const ch = expression[index];
    if (/\s/.test(ch)) {
      index += 1;
      continue;
    }
    if (ch === "(" || ch === ")") {
      tokens.push({ type: ch, value: ch });
      index += 1;
      continue;
    }
    const rest = expression.slice(index);
    const match = /^[A-Za-z0-9.+-]+/.exec(rest);
    if (!match) return null;
    const word = match[0];
    if (word === "AND" || word === "OR") {
      tokens.push({ type: word, value: word });
    } else if (word === "WITH") {
      return null;
    } else {
      tokens.push({ type: "ID", value: word });
    }
    index += word.length;
  }
  return tokens;
}

/**
 * Evaluates an SPDX license expression strictly against `ALLOWED_SPDX_LICENSES`.
 * Fails closed on any GPL/AGPL/LGPL mention, unknown identifier, `SEE LICENSE IN`,
 * `UNLICENSED`, or syntax error.
 */
export function evaluateSpdxLicense(expression) {
  if (typeof expression !== "string") {
    return { allowed: false, reason: "missing_or_non_string_license" };
  }
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    return { allowed: false, reason: "empty_license" };
  }
  if (COPYLEFT_TOKEN_PATTERN.test(trimmed)) {
    return { allowed: false, reason: `disallowed_copyleft_license:${trimmed}` };
  }
  const tokens = tokenizeSpdx(trimmed);
  if (!tokens || tokens.length === 0) {
    return { allowed: false, reason: `unparseable_license:${trimmed}` };
  }

  let cursor = 0;
  function parseOr() {
    let left = parseAnd();
    while (cursor < tokens.length && tokens[cursor]?.type === "OR") {
      cursor += 1;
      const right = parseAnd();
      left = left || right;
    }
    return left;
  }

  function parseAnd() {
    let left = parsePrimary();
    while (cursor < tokens.length && tokens[cursor]?.type === "AND") {
      cursor += 1;
      const right = parsePrimary();
      left = left && right;
    }
    return left;
  }

  function parsePrimary() {
    const token = tokens[cursor];
    if (!token) {
      throw new Error("unexpected_eof");
    }
    if (token.type === "(") {
      cursor += 1;
      const inner = parseOr();
      if (tokens[cursor]?.type !== ")") {
        throw new Error("missing_closing_paren");
      }
      cursor += 1;
      return inner;
    }
    if (token.type === "ID") {
      cursor += 1;
      return ALLOWED_SET.has(token.value);
    }
    throw new Error(`unexpected_token:${token.value}`);
  }

  try {
    const result = parseOr();
    if (cursor !== tokens.length) {
      return { allowed: false, reason: `trailing_tokens:${trimmed}` };
    }
    return result
      ? { allowed: true }
      : { allowed: false, reason: `license_not_in_allowlist:${trimmed}` };
  } catch (error) {
    return {
      allowed: false,
      reason: `unparseable_license:${trimmed}:${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

function resolveLockEntryPath(lockPackages, parentPath, depName) {
  let current = parentPath;
  while (true) {
    const candidate = current
      ? `${current}/node_modules/${depName}`
      : `node_modules/${depName}`;
    if (Object.prototype.hasOwnProperty.call(lockPackages, candidate)) {
      return candidate;
    }
    if (!current) return null;
    const lastSegment = current.lastIndexOf("/node_modules/");
    if (lastSegment >= 0) {
      current = current.slice(0, lastSegment);
    } else {
      current = "";
    }
  }
}

function extractManifestLicense(manifest) {
  if (typeof manifest.license === "string") return manifest.license;
  if (
    manifest.license &&
    typeof manifest.license === "object" &&
    typeof manifest.license.type === "string"
  ) {
    return manifest.license.type;
  }
  if (Array.isArray(manifest.licenses) && manifest.licenses.length > 0) {
    const parts = manifest.licenses
      .map((entry) =>
        typeof entry === "string"
          ? entry
          : entry && typeof entry.type === "string"
            ? entry.type
            : null,
      )
      .filter(Boolean);
    if (parts.length === manifest.licenses.length) {
      return `(${parts.join(" AND ")})`;
    }
  }
  return null;
}

function scanPackageLicenseFiles(pkgAbsDir) {
  const findings = [];
  let entries;
  try {
    entries = readdirSync(pkgAbsDir, { withFileTypes: true });
  } catch {
    return findings;
  }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!/^(license|licence|copying)/i.test(entry.name)) continue;
    const text = readFileSync(join(pkgAbsDir, entry.name), "utf-8");
    for (const pattern of COPYLEFT_TEXT_PATTERNS) {
      if (pattern.test(text)) {
        findings.push(`${entry.name} matches ${pattern.source}`);
      }
    }
  }
  return findings;
}

/**
 * Audits the complete resolved runtime dependency graph of a package directory.
 * Inspects `package.json`, `package-lock.json`, and (by default) every installed
 * runtime package's `package.json` and `LICENSE*` files on disk.
 */
export function auditRuntimeLicenses({
  packageDir,
  verifyInstalled = true,
}) {
  const errors = [];
  const checked = [];

  const pkgPath = resolve(packageDir, "package.json");
  const lockPath = resolve(packageDir, "package-lock.json");
  if (!existsSync(pkgPath)) {
    return { ok: false, checked, errors: [`Missing package.json at ${pkgPath}`] };
  }
  if (!existsSync(lockPath)) {
    return {
      ok: false,
      checked,
      errors: [`Missing package-lock.json at ${lockPath}`],
    };
  }

  const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
  const lock = JSON.parse(readFileSync(lockPath, "utf-8"));

  const rootLicense = extractManifestLicense(pkg);
  const rootCheck = evaluateSpdxLicense(rootLicense);
  if (!rootCheck.allowed) {
    errors.push(`Root package ${pkg.name ?? "<unnamed>"}: ${rootCheck.reason}`);
  }

  if (!lock.packages || typeof lock.packages !== "object") {
    return {
      ok: false,
      checked,
      errors: [...errors, "package-lock.json missing 'packages' map"],
    };
  }

  const lockPackages = lock.packages;
  const runtimePaths = new Set();
  const queue = [];

  const rootDeps = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
  };
  for (const depName of Object.keys(rootDeps)) {
    const resolvedPath = resolveLockEntryPath(lockPackages, "", depName);
    if (!resolvedPath) {
      errors.push(
        `Runtime dependency '${depName}' is missing from package-lock.json`,
      );
      continue;
    }
    if (!runtimePaths.has(resolvedPath)) {
      runtimePaths.add(resolvedPath);
      queue.push(resolvedPath);
    }
  }

  // Also include every non-dev package recorded in the lockfile so nothing slips past graph edges.
  for (const [entryPath, meta] of Object.entries(lockPackages)) {
    if (!entryPath) continue;
    if (meta && meta.dev !== true && meta.devOptional !== true) {
      if (!runtimePaths.has(entryPath)) {
        runtimePaths.add(entryPath);
        queue.push(entryPath);
      }
    }
  }

  while (queue.length > 0) {
    const currentPath = queue.shift();
    const meta = lockPackages[currentPath];
    if (!meta || typeof meta !== "object") {
      errors.push(`Missing lockfile metadata for '${currentPath}'`);
      continue;
    }
    const transitive = {
      ...(meta.dependencies ?? {}),
      ...(meta.optionalDependencies ?? {}),
    };
    for (const depName of Object.keys(transitive)) {
      const resolved = resolveLockEntryPath(lockPackages, currentPath, depName);
      if (!resolved) {
        errors.push(
          `Transitive runtime dependency '${depName}' (from '${currentPath}') is missing from package-lock.json`,
        );
        continue;
      }
      if (!runtimePaths.has(resolved)) {
        runtimePaths.add(resolved);
        queue.push(resolved);
      }
    }
  }

  for (const relPath of [...runtimePaths].sort()) {
    const meta = lockPackages[relPath];
    const pkgName = relPath.replace(/^.*node_modules\//, "");
    const version = meta?.version ?? "unknown";
    const lockLicense = meta?.license ?? null;
    const lockEval = evaluateSpdxLicense(lockLicense);
    if (!lockEval.allowed) {
      errors.push(
        `${pkgName}@${version} (${relPath}) lockfile license failed: ${lockEval.reason}`,
      );
    }

    let diskLicense = null;
    if (verifyInstalled) {
      const absPkgDir = resolve(packageDir, relPath);
      const manifestPath = join(absPkgDir, "package.json");
      if (!existsSync(manifestPath)) {
        errors.push(
          `${pkgName}@${version} (${relPath}) is missing installed package.json`,
        );
      } else {
        const manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));
        diskLicense = extractManifestLicense(manifest);
        const diskEval = evaluateSpdxLicense(diskLicense);
        if (!diskEval.allowed) {
          errors.push(
            `${pkgName}@${version} (${relPath}) manifest license failed: ${diskEval.reason}`,
          );
        }
        if (
          typeof lockLicense === "string" &&
          typeof diskLicense === "string" &&
          lockLicense.trim() !== diskLicense.trim()
        ) {
          errors.push(
            `${pkgName}@${version} (${relPath}) license mismatch: lockfile='${lockLicense}' vs manifest='${diskLicense}'`,
          );
        }
        const copyleftFiles = scanPackageLicenseFiles(absPkgDir);
        for (const finding of copyleftFiles) {
          errors.push(
            `${pkgName}@${version} (${relPath}) license file failed: ${finding}`,
          );
        }
      }
    }

    checked.push({
      path: relPath,
      name: pkgName,
      version,
      license: diskLicense ?? lockLicense,
    });
  }

  return {
    ok: errors.length === 0,
    root: { name: pkg.name, version: pkg.version, license: rootLicense },
    checked,
    errors,
  };
}

/**
 * Runs a clean-room `npm ci --omit=dev --ignore-scripts` in a temporary directory
 * and audits the freshly materialized production dependency tree.
 */
export function runCleanRoomLicenseAudit(packageDir) {
  const scratchDir = mkdtempSync(join(tmpdir(), "entros-verify-licenses-"));
  try {
    copyFileSync(
      resolve(packageDir, "package.json"),
      join(scratchDir, "package.json"),
    );
    copyFileSync(
      resolve(packageDir, "package-lock.json"),
      join(scratchDir, "package-lock.json"),
    );
    const npmBin = process.platform === "win32" ? "npm.cmd" : "npm";
    execFileSync(
      npmBin,
      ["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
      {
        cwd: scratchDir,
        stdio: "pipe",
      },
    );
    return auditRuntimeLicenses({ packageDir: scratchDir, verifyInstalled: true });
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
}

const isCli =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (isCli) {
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const rootDir = resolve(scriptDir, "..");
  const cleanRoom = process.argv.includes("--clean-room");

  const report = cleanRoom
    ? runCleanRoomLicenseAudit(rootDir)
    : auditRuntimeLicenses({ packageDir: rootDir, verifyInstalled: true });

  if (!report.ok) {
    console.error("Runtime license gate FAILED:");
    for (const error of report.errors) {
      console.error(`  - ${error}`);
    }
    process.exit(1);
  }

  const summary = report.checked
    .map((pkg) => `${pkg.name}@${pkg.version} (${pkg.license})`)
    .join(", ");
  console.log(
    `Runtime license gate OK (${cleanRoom ? "clean-room" : "workspace"}): ` +
      `${report.checked.length} runtime packages verified [${summary || "none"}].`,
  );
}
