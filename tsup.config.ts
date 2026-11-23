import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Options } from "tsup";

const rootDir = dirname(fileURLToPath(import.meta.url));
const nobleCompatPath = resolve(rootDir, "src/compat/noble-ed25519-v1.ts");
const nobleCompatAlias = {
  "@noble/curves/ed25519": nobleCompatPath,
  "@noble/hashes/sha2": "@noble/hashes/sha2.js",
};

const nobleCompatNoExternal = [
  /^@noble\/curves\/ed25519$/,
  /^@noble\/hashes\/sha2$/,
];

const nobleV1BridgePlugin: NonNullable<Options["esbuildPlugins"]>[number] = {
  name: "noble-v1-compat-bridge",
  setup(build) {
    build.onResolve({ filter: /^@noble\/curves\/ed25519$/ }, () => ({
      path: nobleCompatPath,
    }));
    build.onResolve({ filter: /^@noble\/hashes\/sha2$/ }, () => ({
      path: "@noble/hashes/sha2.js",
      external: true,
    }));
  },
};

// Published builds ship no source maps and no comments. Whitespace and syntax
// are minified but identifiers are not, so stack traces stay readable.
export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    splitting: false,
    sourcemap: false,
    minifyWhitespace: true,
    minifySyntax: true,
    clean: false,
    external: ["react", "react-dom"],
    noExternal: nobleCompatNoExternal,
    outDir: "dist",
    esbuildPlugins: [nobleV1BridgePlugin],
    esbuildOptions(options) {
      options.alias = { ...options.alias, ...nobleCompatAlias };
    },
    // Inject "use client" so Next.js apps treat the component as client-only
    // without consumers having to add the directive themselves.
    banner: {
      js: '"use client";',
    },
  },
  {
    entry: {
      policy: "src/policy.ts",
      "agent-permit": "src/agent-permit.ts",
      solana: "src/solana/index.ts",
      mcp: "src/mcp/index.ts",
    },
    format: ["esm", "cjs"],
    dts: true,
    splitting: false,
    sourcemap: false,
    minifyWhitespace: true,
    minifySyntax: true,
    clean: false,
    noExternal: nobleCompatNoExternal,
    outDir: "dist",
    esbuildPlugins: [nobleV1BridgePlugin],
    esbuildOptions(options) {
      options.alias = { ...options.alias, ...nobleCompatAlias };
    },
  },
]);
