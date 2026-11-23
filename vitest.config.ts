import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@noble/curves/ed25519": resolve(
        rootDir,
        "src/compat/noble-ed25519-v1.ts",
      ),
      "@noble/hashes/sha2": "@noble/hashes/sha2.js",
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    testTimeout: 10000,
    setupFiles: ["./test/setup.ts"],
  },
});
