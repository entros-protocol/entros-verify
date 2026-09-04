import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    splitting: false,
    sourcemap: true,
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
    entry: ["src/policy.ts"],
    format: ["esm", "cjs"],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: false,
    outDir: "dist",
  },
]);
