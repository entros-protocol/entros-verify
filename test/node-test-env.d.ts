declare module "node:fs" {
  export function readFileSync(
    path: string | URL,
    encoding: "utf-8" | "utf8",
  ): string;
  export function copyFileSync(src: string, dest: string): void;
  export function mkdirSync(path: string, options?: { recursive?: boolean }): void;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(
    path: string,
    options?: { recursive?: boolean; force?: boolean },
  ): void;
  export function symlinkSync(target: string, path: string): void;
  export function writeFileSync(path: string, data: string): void;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
}

declare module "node:os" {
  export function tmpdir(): string;
}

declare module "node:url" {
  export function fileURLToPath(url: string | URL): string;
}

declare module "node:child_process" {
  export interface SpawnSyncReturns {
    readonly status: number | null;
    readonly stdout: string;
    readonly stderr: string;
  }
  export function spawnSync(
    command: string,
    args: readonly string[],
    options?: { encoding?: "utf-8" },
  ): SpawnSyncReturns;
}

declare module "*scripts/check-licenses.mjs" {
  export interface LicenseEvalResult {
    readonly allowed: boolean;
    readonly reason?: string;
  }
  export interface LicenseAuditReport {
    readonly ok: boolean;
    readonly errors: string[];
    readonly checked: Array<{ name: string; license: string }>;
  }
  export function evaluateSpdxLicense(expr: string): LicenseEvalResult;
  export function auditRuntimeLicenses(options: {
    packageDir: string;
    verifyInstalled?: boolean;
  }): LicenseAuditReport;
}

interface NodeBufferStatic {
  from(input: string, encoding?: "utf8" | "utf-8" | "base64" | "base64url"): Uint8Array & {
    toString(encoding?: "utf8" | "utf-8" | "base64" | "base64url"): string;
  };
  from(input: Uint8Array): Uint8Array & {
    toString(encoding?: "utf8" | "utf-8" | "base64" | "base64url"): string;
  };
}

declare const Buffer: NodeBufferStatic;
declare const process: {
  readonly execPath: string;
};
