#!/usr/bin/env node
/**
 * Pre-publish gate. Runs automatically via the `prepublishOnly` npm lifecycle.
 *
 * Guards against the class of leaks where source trees, test fixtures, or
 * scripts get packed into the npm tarball alongside the public `dist/` build.
 * Mirrors the equivalent gate in `pulse-sdk` so the org has one shape.
 *
 * Enforced invariants on package.json:
 *   1. `files` field must exist and be an array (allowlist, not denylist)
 *   2. `files` must include `dist`
 *   3. `files` must not include any of the forbidden entries below, nor
 *      a catch-all like `*` or `.`
 *
 * If someone removes the `files` field, widens it to `*`, or adds a forbidden
 * path, this script fails before npm uploads the tarball.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(scriptDir, "..");
const pkgPath = resolve(rootDir, "package.json");
const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

const FORBIDDEN_PATHS = [
  "src",
  "test",
  "tests",
  "scripts",
  ".npmrc",
  "node_modules",
];

const REQUIRED_EXPORTS = [
  ".",
  "./policy",
  "./agent-permit",
  "./solana",
  "./mcp",
];

const errors = [];

if (!Array.isArray(pkg.files)) {
  errors.push(
    "package.json must define a 'files' allowlist. Without it, npm publish " +
      "ships every non-gitignored path including src/ and test/.",
  );
} else {
  if (!pkg.files.includes("dist")) {
    errors.push("'files' must include 'dist' (the public build output).");
  }

  for (const entry of pkg.files) {
    if (entry === "*" || entry === "." || entry === "**") {
      errors.push(
        `'files' contains catch-all '${entry}', which defeats the allowlist.`,
      );
      continue;
    }
    const normalized = entry.replace(/\/+$/, "");
    if (FORBIDDEN_PATHS.includes(normalized)) {
      errors.push(
        `'files' contains forbidden entry: '${entry}'. Never ship this to npm.`,
      );
    }
    if (FORBIDDEN_PATHS.some((f) => normalized.startsWith(f + "/"))) {
      errors.push(`'files' contains forbidden subpath: '${entry}'.`);
    }
  }
}

if (!pkg.exports || typeof pkg.exports !== "object" || Array.isArray(pkg.exports)) {
  errors.push("package.json must define an 'exports' map.");
} else {
  const distDir = resolve(rootDir, "dist");
  const distExists = existsSync(distDir);

  for (const subpath of REQUIRED_EXPORTS) {
    const target = pkg.exports[subpath];
    if (!target || typeof target !== "object" || Array.isArray(target)) {
      errors.push(`'exports' is missing required subpath '${subpath}'.`);
      continue;
    }
    for (const condition of ["types", "import", "require"]) {
      const value = target[condition];
      if (typeof value !== "string" || !value.startsWith("./dist/")) {
        errors.push(
          `'exports["${subpath}"].${condition}' must point inside './dist/'.`,
        );
        continue;
      }
      if (distExists) {
        const artifactPath = resolve(rootDir, value);
        if (!existsSync(artifactPath)) {
          errors.push(
            `Built artifact missing for '${subpath}' (${condition}): ${value}.`,
          );
        }
      }
    }
  }

  if (distExists) {
    for (const entry of readdirSync(distDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      if (entry.name.endsWith(".map")) {
        errors.push(`Built dist/ contains forbidden source map: ${entry.name}.`);
        continue;
      }
      if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) {
        const contents = readFileSync(resolve(distDir, entry.name), "utf-8");
        if (contents.includes("sourceMappingURL")) {
          errors.push(
            `Built artifact dist/${entry.name} references sourceMappingURL.`,
          );
        }
      }
    }
  }
}

if (errors.length > 0) {
  console.error("prepublish content gate FAILED:");
  for (const e of errors) console.error("  - " + e);
  console.error(
    "\nSee scripts/verify-publish-contents.mjs for the full invariant list.",
  );
  process.exit(1);
}

console.log("prepublish content gate OK: package.json files allowlist is safe.");
