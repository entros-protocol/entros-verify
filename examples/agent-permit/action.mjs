import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";

const DOMAIN = Buffer.alloc(32);
DOMAIN.write("ENTROS_EXAMPLE_AGENT_ACTION_V1", "ascii");
const ALLOWED_RESOURCES = new Set(["synthetic-vault"]);
const KIND_CODES = { grant_access: 1 };

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

/** Validates an action and returns a frozen copy. */
export function canonicalAction(value) {
  if (
    !exactKeys(value, ["kind", "resource", "durationSeconds"]) ||
    value.kind !== "grant_access" ||
    !ALLOWED_RESOURCES.has(value.resource) ||
    !Number.isSafeInteger(value.durationSeconds) ||
    value.durationSeconds < 1 ||
    value.durationSeconds > 3600
  ) {
    throw new Error("Invalid agent action");
  }
  return Object.freeze({
    kind: value.kind,
    resource: value.resource,
    durationSeconds: value.durationSeconds,
  });
}

/**
 * Binary action record: 32-byte domain, agent asset, kind code, SHA-256 of the resource name,
 * and the duration as an unsigned 32-bit big-endian integer. The agent appears in the record
 * as well as in the permit, so the digest names its agent on its own.
 */
export function actionRecord(agent, action) {
  const checked = canonicalAction(action);
  const asset = new PublicKey(agent);
  if (asset.toBase58() !== agent) throw new Error("Invalid agent");
  const record = Buffer.alloc(32 + 32 + 1 + 32 + 4);
  DOMAIN.copy(record, 0);
  asset.toBuffer().copy(record, 32);
  record[64] = KIND_CODES[checked.kind];
  createHash("sha256").update(checked.resource, "utf8").digest().copy(record, 65);
  record.writeUInt32BE(checked.durationSeconds, 97);
  return record;
}

/** The label and digest that the permit request carries for this action. */
export function permitAction(agent, action) {
  const checked = canonicalAction(action);
  return {
    label: `Grant ${checked.resource} access for ${checked.durationSeconds} seconds`,
    sha256: createHash("sha256").update(actionRecord(agent, checked)).digest("hex"),
  };
}
