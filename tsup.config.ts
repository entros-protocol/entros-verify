import { defineConfig } from "tsup";

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
    outDir: "dist",
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
    outDir: "dist",
  },
]);
