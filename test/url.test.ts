import { describe, expect, it } from "vitest";
import { buildPopupUrl, generateRequestId } from "../src/url";

const baseOpts = {
  baseOrigin: "https://entros.io",
  integratorKey: "jupiter",
  parentOrigin: "https://jup.ag",
  cluster: "devnet" as const,
  requestId: "01J9XMR73K8ETBQXP4FZKCG7AK",
};

describe("buildPopupUrl", () => {
  it("produces a valid URL with all required params", () => {
    const url = new URL(buildPopupUrl(baseOpts));
    expect(url.origin).toBe("https://entros.io");
    expect(url.pathname).toBe("/embed/verify-popup");
    expect(url.searchParams.get("integrator")).toBe("jupiter");
    expect(url.searchParams.get("parent_origin")).toBe("https://jup.ag");
    expect(url.searchParams.get("cluster")).toBe("devnet");
    expect(url.searchParams.get("request_id")).toBe("01J9XMR73K8ETBQXP4FZKCG7AK");
    expect(url.searchParams.get("min_trust_score")).toBe(null);
  });

  it("includes min_trust_score when provided", () => {
    const url = new URL(buildPopupUrl({ ...baseOpts, minTrustScore: 100 }));
    expect(url.searchParams.get("min_trust_score")).toBe("100");
  });

  it("rejects integrator keys with invalid characters", () => {
    expect(() => buildPopupUrl({ ...baseOpts, integratorKey: "Jupiter" })).toThrow(
      /Invalid integratorKey/,
    );
    expect(() => buildPopupUrl({ ...baseOpts, integratorKey: "jup ag" })).toThrow(
      /Invalid integratorKey/,
    );
    expect(() => buildPopupUrl({ ...baseOpts, integratorKey: "" })).toThrow(
      /Invalid integratorKey/,
    );
  });

  it("rejects integrator keys longer than 64 chars", () => {
    const long = "a".repeat(65);
    expect(() => buildPopupUrl({ ...baseOpts, integratorKey: long })).toThrow(
      /Invalid integratorKey/,
    );
  });

  it("accepts hyphens and underscores in integrator keys", () => {
    expect(() =>
      buildPopupUrl({ ...baseOpts, integratorKey: "jup_ag-v2" }),
    ).not.toThrow();
  });

  it("rejects parent origins without scheme", () => {
    expect(() => buildPopupUrl({ ...baseOpts, parentOrigin: "jup.ag" })).toThrow(
      /Invalid parentOrigin/,
    );
  });

  it("rejects parent origins with paths", () => {
    expect(() =>
      buildPopupUrl({ ...baseOpts, parentOrigin: "https://jup.ag/path" }),
    ).toThrow(/Invalid parentOrigin/);
  });

  it("rejects min_trust_score out of [0, 10000]", () => {
    expect(() => buildPopupUrl({ ...baseOpts, minTrustScore: -1 })).toThrow(
      /Invalid minTrustScore/,
    );
    expect(() => buildPopupUrl({ ...baseOpts, minTrustScore: 10001 })).toThrow(
      /Invalid minTrustScore/,
    );
  });

  it("rejects non-integer min_trust_score", () => {
    expect(() => buildPopupUrl({ ...baseOpts, minTrustScore: 100.5 })).toThrow(
      /Invalid minTrustScore/,
    );
  });

  it("works for mainnet-beta cluster (v2 surface)", () => {
    const url = new URL(buildPopupUrl({ ...baseOpts, cluster: "mainnet-beta" }));
    expect(url.searchParams.get("cluster")).toBe("mainnet-beta");
  });

  it("respects baseOrigin override (E2E testing)", () => {
    const url = new URL(
      buildPopupUrl({ ...baseOpts, baseOrigin: "http://localhost:3000" }),
    );
    expect(url.origin).toBe("http://localhost:3000");
    expect(url.pathname).toBe("/embed/verify-popup");
  });
});

describe("generateRequestId", () => {
  it("returns a non-empty string", () => {
    const id = generateRequestId();
    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(8);
  });

  it("returns a different value each call", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(generateRequestId());
    }
    expect(ids.size).toBe(100);
  });
});
