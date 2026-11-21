// @vitest-environment node
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  auditRuntimeLicenses,
  evaluateSpdxLicense,
} from "../scripts/check-licenses.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function withTempPackage(
  setup: (dir: string) => void,
  run: (dir: string) => void,
) {
  const dir = mkdtempSync(join(tmpdir(), "entros-license-test-"));
  try {
    setup(dir);
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function writeJson(path: string, data: unknown) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2));
}

describe("scripts/check-licenses.mjs", () => {
  it("accepts strictly permissive SPDX expressions", () => {
    for (const expr of [
      "MIT",
      "Apache-2.0",
      "BSD-2-Clause",
      "BSD-3-Clause",
      "ISC",
      "(MIT OR Apache-2.0)",
      "(MIT AND ISC)",
      "(BSD-2-Clause OR BSD-3-Clause)",
    ]) {
      expect(evaluateSpdxLicense(expr), expr).toEqual({ allowed: true });
    }
  });

  it("fails closed on GPL, AGPL, LGPL, copyleft, unknown, or malformed licenses", () => {
    for (const expr of [
      "GPL-3.0",
      "GPL-3.0-only",
      "GPL-3.0-or-later",
      "GPL-2.0",
      "AGPL-3.0",
      "AGPL-3.0-only",
      "LGPL-2.1",
      "LGPL-3.0",
      "(MIT AND GPL-3.0)",
      "(MIT OR GPL-3.0-only)",
      "MPL-2.0",
      "UNLICENSED",
      "SEE LICENSE IN LICENSE.md",
      "",
      "   ",
      "(MIT",
      "MIT WITH Classpath-exception-2.0",
      null,
      undefined,
    ]) {
      const result = evaluateSpdxLicense(expr as string);
      expect(result.allowed, String(expr)).toBe(false);
    }
  });

  it("passes on the live @entros/verify workspace runtime dependency graph", () => {
    const report = auditRuntimeLicenses({
      packageDir: REPO_ROOT,
      verifyInstalled: true,
    });
    expect(report.ok).toBe(true);
    expect(report.errors).toEqual([]);
    expect(report.checked.map((p: { name: string }) => p.name)).toEqual([
      "@noble/curves",
      "@noble/hashes",
    ]);
  });

  it("fails closed on direct or transitive GPL/AGPL/LGPL dependencies", () => {
    withTempPackage(
      (dir) => {
        writeJson(join(dir, "package.json"), {
          name: "synthetic-app",
          version: "1.0.0",
          license: "MIT",
          dependencies: { "mit-wrapper": "^1.0.0" },
        });
        writeJson(join(dir, "package-lock.json"), {
          name: "synthetic-app",
          version: "1.0.0",
          lockfileVersion: 3,
          packages: {
            "": {
              name: "synthetic-app",
              version: "1.0.0",
              license: "MIT",
              dependencies: { "mit-wrapper": "^1.0.0" },
            },
            "node_modules/mit-wrapper": {
              version: "1.0.0",
              license: "MIT",
              dependencies: { "gpl-leaf": "^1.0.0" },
            },
            "node_modules/gpl-leaf": {
              version: "1.0.0",
              license: "GPL-3.0-only",
            },
          },
        });
        writeJson(join(dir, "node_modules/mit-wrapper/package.json"), {
          name: "mit-wrapper",
          version: "1.0.0",
          license: "MIT",
        });
        writeJson(join(dir, "node_modules/gpl-leaf/package.json"), {
          name: "gpl-leaf",
          version: "1.0.0",
          license: "GPL-3.0-only",
        });
      },
      (dir) => {
        const report = auditRuntimeLicenses({
          packageDir: dir,
          verifyInstalled: true,
        });
        expect(report.ok).toBe(false);
        expect(
          report.errors.some((e: string) => e.includes("gpl-leaf")),
        ).toBe(true);
      },
    );
  });

  it("fails closed when installed manifest or LICENSE text contradicts an MIT lockfile entry", () => {
    withTempPackage(
      (dir) => {
        writeJson(join(dir, "package.json"), {
          name: "synthetic-app",
          version: "1.0.0",
          license: "MIT",
          dependencies: { "sneaky-pkg": "^1.0.0" },
        });
        writeJson(join(dir, "package-lock.json"), {
          name: "synthetic-app",
          version: "1.0.0",
          lockfileVersion: 3,
          packages: {
            "": {
              name: "synthetic-app",
              version: "1.0.0",
              license: "MIT",
              dependencies: { "sneaky-pkg": "^1.0.0" },
            },
            "node_modules/sneaky-pkg": {
              version: "1.0.0",
              license: "MIT",
            },
          },
        });
        writeJson(join(dir, "node_modules/sneaky-pkg/package.json"), {
          name: "sneaky-pkg",
          version: "1.0.0",
          license: "MIT",
        });
        writeFileSync(
          join(dir, "node_modules/sneaky-pkg/LICENSE"),
          "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n",
        );
      },
      (dir) => {
        const report = auditRuntimeLicenses({
          packageDir: dir,
          verifyInstalled: true,
        });
        expect(report.ok).toBe(false);
        expect(
          report.errors.some((e: string) => e.includes("license file failed")),
        ).toBe(true);
      },
    );
  });
});
