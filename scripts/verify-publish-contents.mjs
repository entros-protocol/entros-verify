#!/usr/bin/env node
/**
 * Pre-publish gate. Runs automatically via the `prepublishOnly` npm lifecycle.
 *
 * Guards against shipping source trees, Python SDK files, shared parity vectors,
 * tests, source maps, or accidental React imports in headless entrypoints.
 *
 * Enforced invariants on package.json and dist/:
 *   1. `files` field must exist and be an allowlist array containing `dist`
 *   2. `files` must not include `src`, `test`, `scripts`, `python`, `spec`, etc.
 *   3. Every required subpath export resolves to built files in `./dist/`
 *   4. Zero `.map` files and zero `sourceMappingURL` references in `dist/`
 *   5. `"use client"` banner appears on `dist/react.*` and never on headless entries
 *   6. Headless entries never import `react` or `react-dom`
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const rootDir = resolve(scriptDir, "..");
const pkgPath = resolve(rootDir, "package.json");
const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

const FORBIDDEN_PATHS = [
  "src",
  "test",
  "tests",
  "scripts",
  "python",
  "spec",
  "example",
  "examples",
  ".agents",
  ".npmrc",
  "node_modules",
];

const REQUIRED_EXPORTS = [
  ".",
  "./voice",
  "./permit",
  "./mcp",
  "./browser-signals",
  "./solana",
  "./policy",
  "./agent-permit",
  "./react",
];

const HEADLESS_ENTRIES = [
  "index",
  "voice",
  "permit",
  "mcp",
  "browser-signals",
  "solana",
  "policy",
  "agent-permit",
];

const errors = [];

if (!Array.isArray(pkg.files)) {
  errors.push(
    "package.json must define a 'files' allowlist. Without it, npm publish " +
      "ships every non-gitignored path including src/, python/, and spec/.",
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

if (
  !pkg.exports ||
  typeof pkg.exports !== "object" ||
  Array.isArray(pkg.exports)
) {
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
        if (condition === "types") {
          const dmtsPath = artifactPath.replace(/\.d\.ts$/, ".d.mts");
          if (!existsSync(dmtsPath)) {
            errors.push(
              `Built ESM declaration missing for '${subpath}': ${dmtsPath}.`,
            );
          }
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

    for (const name of HEADLESS_ENTRIES) {
      for (const ext of [".mjs", ".js"]) {
        const artifactPath = resolve(distDir, `${name}${ext}`);
        if (!existsSync(artifactPath)) continue;
        const contents = readFileSync(artifactPath, "utf-8");
        if (contents.startsWith('"use client"') || contents.startsWith("'use client'")) {
          errors.push(
            `Headless entrypoint dist/${name}${ext} must not emit a "use client" banner.`,
          );
        }
        if (/from\s*["']react(?:-dom|\/jsx-runtime)?["']|require\(\s*["']react(?:-dom|\/jsx-runtime)?["']\s*\)/.test(contents)) {
          errors.push(
            `Headless entrypoint dist/${name}${ext} must not import React.`,
          );
        }
      }
    }

    for (const ext of [".mjs", ".js"]) {
      const reactPath = resolve(distDir, `react${ext}`);
      if (!existsSync(reactPath)) continue;
      const contents = readFileSync(reactPath, "utf-8");
      if (!contents.startsWith('"use client";')) {
        errors.push(
          `React entrypoint dist/react${ext} must start with '"use client";'.`,
        );
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

console.log(
  "prepublish content gate OK: package.json files allowlist, 9 subpath exports, and headless boundaries verified.",
);
