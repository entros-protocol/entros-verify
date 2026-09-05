import { randomBytes, createPublicKey, verify } from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_CHALLENGE_LIFETIME_SECONDS = 120;
const MAX_PENDING_CHALLENGES = 1000;
const ALLOWED_RESOURCE = "synthetic-vault";

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function canonicalAction(value) {
  if (
    !exactKeys(value, ["kind", "resource", "durationSeconds"]) ||
    value.kind !== "grant_access" ||
    value.resource !== ALLOWED_RESOURCE ||
    !Number.isSafeInteger(value.durationSeconds) ||
    value.durationSeconds < 1 ||
    value.durationSeconds > 3600
  ) {
    throw new Error("Invalid protected action");
  }
  return Object.freeze({
    kind: value.kind,
    resource: value.resource,
    durationSeconds: value.durationSeconds,
  });
}

export function signingBytes(challenge) {
  if (
    !exactKeys(challenge, [
      "version",
      "wallet",
      "action",
      "audience",
      "nonce",
      "issuedAt",
      "expiresAt",
    ]) ||
    challenge.version !== 1 ||
    typeof challenge.wallet !== "string" ||
    typeof challenge.audience !== "string" ||
    typeof challenge.nonce !== "string" ||
    !/^[a-f0-9]{64}$/.test(challenge.nonce) ||
    !Number.isSafeInteger(challenge.issuedAt) ||
    !Number.isSafeInteger(challenge.expiresAt) ||
    challenge.issuedAt < 1 ||
    challenge.expiresAt <= challenge.issuedAt
  ) {
    throw new Error("Invalid action challenge");
  }
  return Buffer.from(
    JSON.stringify({
      domain: "entros-local-protected-action",
      version: challenge.version,
      wallet: challenge.wallet,
      action: canonicalAction(challenge.action),
      audience: challenge.audience,
      nonce: challenge.nonce,
      issuedAt: challenge.issuedAt,
      expiresAt: challenge.expiresAt,
    }),
    "utf8",
  );
}

export class LocalPolicySettlement {
  #pending = new Map();
  #actions = [];
  #policy;
  #audience;
  #readEvidence;
  #evaluatePolicy;
  #decodeWallet;
  #clock;

  constructor({
    policy,
    audience,
    readEvidence,
    evaluatePolicy,
    decodeWallet,
    nowSeconds,
  }) {
    if (
      typeof audience !== "string" ||
      !/^http:\/\/127\.0\.0\.1(?::[0-9]+)?\/local-action$/.test(audience)
    ) {
      throw new Error("Only a loopback action audience is supported");
    }
    this.#policy = structuredClone(policy);
    this.#audience = audience;
    this.#readEvidence = readEvidence;
    this.#evaluatePolicy = evaluatePolicy;
    this.#decodeWallet = decodeWallet;
    this.#clock = nowSeconds;
  }

  #now() {
    const now = this.#clock();
    if (!Number.isSafeInteger(now) || now < 1)
      throw new Error("Invalid server clock");
    return now;
  }

  #walletBytes(wallet) {
    const bytes = this.#decodeWallet(wallet);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32)
      throw new Error("Invalid wallet");
    return bytes;
  }

  issue(wallet, action) {
    this.#walletBytes(wallet);
    const now = this.#now();
    for (const [nonce, item] of this.#pending)
      if (item.challenge.expiresAt <= now) this.#pending.delete(nonce);
    if (this.#pending.size >= MAX_PENDING_CHALLENGES)
      throw new Error("Challenge capacity reached");
    const challenge = Object.freeze({
      version: 1,
      wallet,
      action: canonicalAction(action),
      audience: this.#audience,
      nonce: randomBytes(32).toString("hex"),
      issuedAt: now,
      expiresAt: now + MAX_CHALLENGE_LIFETIME_SECONDS,
    });
    this.#pending.set(challenge.nonce, {
      challenge,
      bytes: signingBytes(challenge),
    });
    return structuredClone(challenge);
  }

  async settle(request) {
    if (
      !request ||
      typeof request !== "object" ||
      !exactKeys(request.challenge, [
        "version",
        "wallet",
        "action",
        "audience",
        "nonce",
        "issuedAt",
        "expiresAt",
      ])
    )
      return { ok: false, reason: "invalid_request" };
    const pending = this.#pending.get(request.challenge.nonce);
    if (!pending) return { ok: false, reason: "nonce_unavailable" };
    let bytes;
    try {
      bytes = signingBytes(request.challenge);
    } catch {
      return { ok: false, reason: "invalid_request" };
    }
    if (!bytes.equals(pending.bytes))
      return { ok: false, reason: "challenge_mismatch" };
    if (this.#now() >= pending.challenge.expiresAt)
      return { ok: false, reason: "challenge_expired" };
    if (
      typeof request.signature !== "string" ||
      !/^[a-f0-9]{128}$/.test(request.signature)
    ) {
      return { ok: false, reason: "invalid_signature" };
    }
    const publicKey = createPublicKey({
      key: Buffer.concat([
        ED25519_SPKI_PREFIX,
        this.#walletBytes(pending.challenge.wallet),
      ]),
      format: "der",
      type: "spki",
    });
    if (!verify(null, bytes, publicKey, Buffer.from(request.signature, "hex")))
      return { ok: false, reason: "invalid_signature" };
    if (
      typeof request.verifiedTransaction !== "string" ||
      request.verifiedTransaction.length < 1 ||
      request.verifiedTransaction.length > 128
    )
      return { ok: false, reason: "invalid_transaction" };

    let evidence;
    try {
      evidence = await this.#readEvidence({
        wallet: pending.challenge.wallet,
        signature: request.verifiedTransaction,
      });
    } catch {
      return { ok: false, reason: "state_unavailable" };
    }
    const now = this.#now();
    let policyResult;
    try {
      policyResult = this.#evaluatePolicy(this.#policy, evidence, now);
    } catch {
      return { ok: false, reason: "invalid_evidence" };
    }
    if (policyResult.decision !== "allow")
      return { ok: false, reason: policyResult.reason };
    if (
      policyResult.evidence?.identity.walletPubkey !==
        pending.challenge.wallet ||
      policyResult.evidence?.transaction.signature !==
        request.verifiedTransaction ||
      !Number.isSafeInteger(policyResult.expiresAt) ||
      now >= policyResult.expiresAt
    ) {
      return { ok: false, reason: "invalid_evidence" };
    }
    if (now >= pending.challenge.expiresAt)
      return { ok: false, reason: "challenge_expired" };
    if (this.#pending.get(pending.challenge.nonce) !== pending)
      return { ok: false, reason: "nonce_unavailable" };

    const action = Object.freeze({
      id: this.#actions.length + 1,
      wallet: pending.challenge.wallet,
      ...pending.challenge.action,
      expiresAt: now + pending.challenge.action.durationSeconds,
      verifiedTransaction: request.verifiedTransaction,
      settledAt: now,
    });
    this.#pending.delete(pending.challenge.nonce);
    this.#actions.push(action);
    return { ok: true, action: structuredClone(action) };
  }

  actions() {
    return structuredClone(this.#actions);
  }
}
