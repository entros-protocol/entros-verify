import {
  type AccountOwnerLike,
  type AddressInput,
  base58Encode,
  ownerMatches,
} from "./address";
import { SOLANA_PROGRAM_IDS } from "./constants";
import { normalizeAccountData } from "./rpc";

/** On-chain identity state mirroring the Entros Anchor `IdentityState` account. */
export interface IdentityState {
  owner: string;
  creationTimestamp: number;
  lastVerificationTimestamp: number;
  verificationCount: number;
  trustScore: number;
  currentCommitment: Uint8Array;
  mint: string;
  lastResetTimestamp: number;
  projectionVersion: number;
  lastRebaselineTimestamp?: number;
}

export type MigrationRecordRead =
  | { status: "none" }
  | { status: "migrated"; migratedAt: number }
  | { status: "invalid" };

export interface MigrationRecordAccount {
  data: Uint8Array | readonly [string, string];
  executable?: boolean;
  owner?: AccountOwnerLike;
}

export const IDENTITY_STATE_DISCRIMINATOR = Object.freeze([
  156, 32, 87, 93, 52, 155, 248, 207,
] as const);

/** Current `IdentityState` layout byte length. */
export const IDENTITY_STATE_LEN = 593;

/** Oldest prefix-compatible `IdentityState` layout length. */
export const OLDEST_PREFIX_COMPATIBLE_LEN = 543;

/** Accepted `IdentityState` account lengths across layout upgrades. */
export const SUPPORTED_IDENTITY_STATE_LENGTHS = Object.freeze([
  543, 551, 583, 593,
] as const);

export const MIGRATION_RECORD_DISCRIMINATOR = Object.freeze([
  16, 36, 116, 243, 192, 61, 40, 1,
] as const);

/** Minimum byte length of a `MigrationRecord` through `previous_wallet`. */
export const MIGRATION_RECORD_SIZE = 57;
const MIGRATED_AT_OFFSET = 8;

const IDENTITY_OFFSETS = Object.freeze({
  owner: 8,
  creationTimestamp: 40,
  lastVerificationTimestamp: 48,
  verificationCount: 56,
  trustScore: 60,
  currentCommitment: 62,
  mint: 94,
  bump: 126,
  recentTimestamps: 127,
  lastResetTimestamp: 543,
  newWallet: 551,
  projectionVersion: 583,
  lastRebaselineTimestamp: 585,
});

function readSafeI64LE(view: DataView, offset: number): number | null {
  const value = Number(view.getBigInt64(offset, true));
  return Number.isSafeInteger(value) ? value : null;
}

function padToCurrentLayout(accountData: Uint8Array): Uint8Array | null {
  if (accountData.length >= IDENTITY_STATE_LEN) return accountData;
  if (accountData.length < OLDEST_PREFIX_COMPATIBLE_LEN) return null;
  const grown = new Uint8Array(IDENTITY_STATE_LEN);
  grown.set(accountData);
  return grown;
}

/**
 * Decodes raw `IdentityState` account bytes using pure Borsh layout parsing.
 * Legacy 543, 551, and 583-byte accounts are zero-padded to the current 593-byte
 * layout because every upgrade appended fields to the end. Returns null on an
 * unrecognized discriminator, truncated layout, or unsafe 64-bit integer.
 */
export function decodeIdentityState(
  accountData: Uint8Array,
): IdentityState | null {
  if (!(accountData instanceof Uint8Array)) return null;
  const data = padToCurrentLayout(accountData);
  if (!data) return null;
  for (let i = 0; i < IDENTITY_STATE_DISCRIMINATOR.length; i += 1) {
    if (data[i] !== IDENTITY_STATE_DISCRIMINATOR[i]) return null;
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const creationTimestamp = readSafeI64LE(
    view,
    IDENTITY_OFFSETS.creationTimestamp,
  );
  const lastVerificationTimestamp = readSafeI64LE(
    view,
    IDENTITY_OFFSETS.lastVerificationTimestamp,
  );
  const lastResetTimestamp = readSafeI64LE(
    view,
    IDENTITY_OFFSETS.lastResetTimestamp,
  );
  const lastRebaselineTimestamp = readSafeI64LE(
    view,
    IDENTITY_OFFSETS.lastRebaselineTimestamp,
  );
  if (
    creationTimestamp === null ||
    lastVerificationTimestamp === null ||
    lastResetTimestamp === null ||
    lastRebaselineTimestamp === null
  ) {
    return null;
  }

  return {
    owner: base58Encode(
      data.subarray(IDENTITY_OFFSETS.owner, IDENTITY_OFFSETS.owner + 32),
    ),
    creationTimestamp,
    lastVerificationTimestamp,
    verificationCount: view.getUint32(IDENTITY_OFFSETS.verificationCount, true),
    trustScore: view.getUint16(IDENTITY_OFFSETS.trustScore, true),
    currentCommitment: new Uint8Array(
      data.subarray(
        IDENTITY_OFFSETS.currentCommitment,
        IDENTITY_OFFSETS.currentCommitment + 32,
      ),
    ),
    mint: base58Encode(
      data.subarray(IDENTITY_OFFSETS.mint, IDENTITY_OFFSETS.mint + 32),
    ),
    lastResetTimestamp,
    projectionVersion: view.getUint16(IDENTITY_OFFSETS.projectionVersion, true),
    lastRebaselineTimestamp,
  };
}

/**
 * Parses a wallet's `MigrationRecord` PDA. An absent account or an account
 * owned by another program reads as `{ status: "none" }` because anyone can
 * fund the address with lamports. Any Anchor-owned account that does not parse
 * as a valid 57+-byte `MigrationRecord` returns `{ status: "invalid" }`.
 */
export function readMigrationRecord(
  account: MigrationRecordAccount | null | undefined,
  anchorProgram: AddressInput = SOLANA_PROGRAM_IDS.anchor,
): MigrationRecordRead {
  if (!account || !ownerMatches(account.owner, anchorProgram)) {
    return { status: "none" };
  }
  const data = normalizeAccountData(account.data);
  if (
    account.executable === true ||
    !data ||
    data.length < MIGRATION_RECORD_SIZE ||
    !MIGRATION_RECORD_DISCRIMINATOR.every(
      (byte, index) => data[index] === byte,
    )
  ) {
    return { status: "invalid" };
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const migratedAt = Number(view.getBigInt64(MIGRATED_AT_OFFSET, true));
  if (!Number.isSafeInteger(migratedAt) || migratedAt < 1) {
    return { status: "invalid" };
  }
  return { status: "migrated", migratedAt };
}
