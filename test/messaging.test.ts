import { describe, expect, it } from "vitest";
import {
  isEntrosMessage,
  isErrorPayload,
  isFreshMessage,
  isHeartbeatPayload,
  isVerifiedPayload,
} from "../src/messaging";
import type { EntrosMessage } from "../src/types";

const validMessage: EntrosMessage = {
  version: 1,
  source: "entros",
  type: "entros/verified",
  request_id: "01J9XMR73K8ETBQXP4FZKCG7AK",
  timestamp: Date.now(),
  payload: {},
};

describe("isEntrosMessage", () => {
  it("accepts a well-formed envelope", () => {
    expect(isEntrosMessage(validMessage)).toBe(true);
  });

  it("rejects null and primitives", () => {
    expect(isEntrosMessage(null)).toBe(false);
    expect(isEntrosMessage(undefined)).toBe(false);
    expect(isEntrosMessage("entros")).toBe(false);
    expect(isEntrosMessage(42)).toBe(false);
  });

  it("rejects wrong source", () => {
    expect(isEntrosMessage({ ...validMessage, source: "phishing" })).toBe(false);
  });

  it("rejects wrong version", () => {
    expect(isEntrosMessage({ ...validMessage, version: 2 })).toBe(false);
  });

  it("rejects unknown message type", () => {
    expect(isEntrosMessage({ ...validMessage, type: "entros/hijack" })).toBe(false);
  });

  it("rejects missing request_id", () => {
    const { request_id, ...rest } = validMessage;
    void request_id;
    expect(isEntrosMessage(rest)).toBe(false);
  });

  it("rejects empty request_id", () => {
    expect(isEntrosMessage({ ...validMessage, request_id: "" })).toBe(false);
  });

  it("rejects non-finite timestamp", () => {
    expect(isEntrosMessage({ ...validMessage, timestamp: Infinity })).toBe(false);
    expect(isEntrosMessage({ ...validMessage, timestamp: NaN })).toBe(false);
  });

  it("rejects when payload key is missing entirely", () => {
    const { payload, ...rest } = validMessage;
    void payload;
    expect(isEntrosMessage(rest)).toBe(false);
  });
});

describe("isFreshMessage", () => {
  it("accepts a message within the 90-second freshness window", () => {
    const now = 1_000_000_000_000;
    expect(isFreshMessage({ ...validMessage, timestamp: now }, now)).toBe(true);
    expect(isFreshMessage({ ...validMessage, timestamp: now - 60_000 }, now)).toBe(true);
    expect(isFreshMessage({ ...validMessage, timestamp: now + 60_000 }, now)).toBe(true);
  });

  it("rejects messages older than 90 seconds", () => {
    const now = 1_000_000_000_000;
    expect(isFreshMessage({ ...validMessage, timestamp: now - 6 * 60_000 }, now)).toBe(false);
  });

  it("rejects messages from too far in the future", () => {
    const now = 1_000_000_000_000;
    expect(isFreshMessage({ ...validMessage, timestamp: now + 6 * 60_000 }, now)).toBe(false);
  });
});

describe("isVerifiedPayload", () => {
  const valid = {
    wallet_pubkey: "11111111111111111111111111111111",
    attestation_pda: "22222222222222222222222222222222",
    tx_sig: "sig-base58",
    trust_score: 250,
    cluster: "devnet" as const,
  };

  it("accepts a well-formed verified payload", () => {
    expect(isVerifiedPayload(valid)).toBe(true);
  });

  it("rejects unknown cluster", () => {
    expect(isVerifiedPayload({ ...valid, cluster: "localnet" })).toBe(false);
  });

  it("rejects negative trust_score", () => {
    expect(isVerifiedPayload({ ...valid, trust_score: -1 })).toBe(false);
  });

  it("rejects empty wallet_pubkey", () => {
    expect(isVerifiedPayload({ ...valid, wallet_pubkey: "" })).toBe(false);
  });

  it("rejects null and primitives", () => {
    expect(isVerifiedPayload(null)).toBe(false);
    expect(isVerifiedPayload("done")).toBe(false);
  });
});

describe("isErrorPayload", () => {
  it("accepts known reason codes", () => {
    expect(isErrorPayload({ reason: "wallet_rejected" })).toBe(true);
    expect(isErrorPayload({ reason: "validation_failed" })).toBe(true);
    expect(isErrorPayload({ reason: "timeout" })).toBe(true);
    expect(isErrorPayload({ reason: "unknown" })).toBe(true);
  });

  it("rejects reason codes outside the public allowlist", () => {
    expect(isErrorPayload({ reason: "internal_only_signal_alpha" })).toBe(false);
    expect(isErrorPayload({ reason: "internal_only_signal_beta" })).toBe(false);
    expect(isErrorPayload({ reason: "" })).toBe(false);
    expect(isErrorPayload({ reason: "WALLET_REJECTED" })).toBe(false); // case-sensitive
  });

  it("rejects non-objects", () => {
    expect(isErrorPayload("wallet_rejected")).toBe(false);
    expect(isErrorPayload(null)).toBe(false);
  });
});

describe("isHeartbeatPayload", () => {
  it("accepts known statuses", () => {
    expect(isHeartbeatPayload({ status: "wallet_connecting" })).toBe(true);
    expect(isHeartbeatPayload({ status: "capturing" })).toBe(true);
    expect(isHeartbeatPayload({ status: "proving" })).toBe(true);
    expect(isHeartbeatPayload({ status: "submitting" })).toBe(true);
    expect(isHeartbeatPayload({ status: "attesting" })).toBe(true);
  });

  it("rejects unknown statuses", () => {
    expect(isHeartbeatPayload({ status: "thinking" })).toBe(false);
  });
});
