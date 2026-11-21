import {
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveSasAttestationPda,
  ownerMatches,
  parseSolanaAddress,
  SolanaAddress,
} from "./address";
import {
  IDENTITY_STATE_DISCRIMINATOR,
  readMigrationRecord,
} from "./accounts";
import { SAS_DEVNET_CONFIG, SOLANA_PROGRAM_IDS } from "./constants";
import {
  normalizeAccountInfo,
  resolveSolanaConnection,
  type RawAccountInfoLike,
  type SolanaTransport,
} from "./rpc";

const IDENTITY_CREATION_TIMESTAMP_OFFSET = 40;
const IDENTITY_TRUST_SCORE_OFFSET = 60;
const IDENTITY_LAST_RESET_TIMESTAMP_OFFSET = 543;
const IDENTITY_MIN_SIZE = 62;
const IDENTITY_RESET_SIZE = 551;

/** Decoded Entros attestation from the Solana Attestation Service. */
export interface EntrosAttestation {
  isHuman: boolean;
  trustScore: number;
  verifiedAt: number;
  mode: string;
  expired: boolean;
}

export interface VerifyEntrosAttestationOptions {
  /** Override current Unix timestamp in seconds for deterministic checks. */
  nowSeconds?: number;
}

function readI64LE(view: DataView, offset: number): number | null {
  const value = Number(view.getBigInt64(offset, true));
  return Number.isSafeInteger(value) ? value : null;
}

function deserializeIdentityStateCrossCheck(
  raw: Uint8Array,
): {
  trustScore: number;
  lastResetTimestamp: number;
  creationTimestamp: number;
} | null {
  if (raw.length < IDENTITY_MIN_SIZE) return null;
  for (let i = 0; i < IDENTITY_STATE_DISCRIMINATOR.length; i += 1) {
    if (raw[i] !== IDENTITY_STATE_DISCRIMINATOR[i]) return null;
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const creationTimestamp = readI64LE(view, IDENTITY_CREATION_TIMESTAMP_OFFSET);
  if (creationTimestamp === null) return null;
  const trustScore = view.getUint16(IDENTITY_TRUST_SCORE_OFFSET, true);
  const lastResetTimestamp =
    raw.length >= IDENTITY_RESET_SIZE
      ? readI64LE(view, IDENTITY_LAST_RESET_TIMESTAMP_OFFSET)
      : 0;
  if (lastResetTimestamp === null) return null;
  return { trustScore, lastResetTimestamp, creationTimestamp };
}

/**
 * Deserializes a SAS Attestation account matching `serialize_attestation_data`:
 * 1-byte discriminator, 32-byte nonce, 32-byte credential, 32-byte schema,
 * length-prefixed data (`[bool, u16, i64, string]`), 32-byte signer,
 * 8-byte i64 expiry, and 32-byte token account.
 */
function deserializeSasAttestation(
  raw: Uint8Array,
  nowSeconds: number,
): EntrosAttestation | null {
  if (raw.length < 173) return null;
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);

  let offset = 1 + 96;
  const dataLen = view.getUint32(offset, true);
  offset += 4;

  if (raw.length < offset + dataLen + 32 + 8 + 32) return null;

  const attestationData = raw.subarray(offset, offset + dataLen);
  offset += dataLen;

  // Skip signer pubkey (32 bytes).
  offset += 32;

  const expiry = readI64LE(view, offset);
  if (expiry === null || expiry < 0) return null;

  if (attestationData.length < 11) return null;
  const data = new DataView(
    attestationData.buffer,
    attestationData.byteOffset,
    attestationData.byteLength,
  );

  let dataOffset = 0;
  const isHuman = attestationData[dataOffset] === 1;
  dataOffset += 1;

  const trustScore = data.getUint16(dataOffset, true);
  dataOffset += 2;

  const verifiedAt = readI64LE(data, dataOffset);
  if (verifiedAt === null) return null;
  dataOffset += 8;

  let mode = "unknown";
  if (dataOffset + 4 <= attestationData.length) {
    const modeLen = data.getUint32(dataOffset, true);
    dataOffset += 4;
    if (dataOffset + modeLen <= attestationData.length) {
      mode = new TextDecoder().decode(
        attestationData.subarray(dataOffset, dataOffset + modeLen),
      );
    }
  }

  const expired = expiry > 0 && nowSeconds >= expiry;
  return { isHuman, trustScore, verifiedAt, mode, expired };
}

/**
 * Checks whether a wallet holds a current Entros SAS attestation on devnet.
 *
 * Fetches the attestation PDA, `IdentityState` PDA, and 57-byte `MigrationRecord`
 * PDA in a single RPC batch, cross-checks `trustScore` and reset timestamps, and
 * returns `null` when the attestation predates account creation or migration.
 */
export async function verifyEntrosAttestation(
  walletAddress: string,
  connection: SolanaTransport,
  options?: VerifyEntrosAttestationOptions,
): Promise<EntrosAttestation | null> {
  try {
    const wallet = parseSolanaAddress(walletAddress);
    if (!wallet) return null;
    const nowSeconds = options?.nowSeconds ?? Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) return null;

    const client = resolveSolanaConnection(connection);
    const sasProgram = new SolanaAddress(SAS_DEVNET_CONFIG.programId);
    const anchorProgram = new SolanaAddress(SOLANA_PROGRAM_IDS.anchor);

    const [attestationAddress] = deriveSasAttestationPda(wallet);
    const [identityAddress] = deriveIdentityPda(wallet);
    const [migrationAddress] = deriveMigrationRecordPda(wallet);

    const attestationPda = new SolanaAddress(attestationAddress);
    const identityPda = new SolanaAddress(identityAddress);
    const migrationPda = new SolanaAddress(migrationAddress);

    let batch: (RawAccountInfoLike | null | undefined)[];
    if (typeof client.getMultipleAccountsInfo === "function") {
      batch = await client.getMultipleAccountsInfo([
        attestationPda,
        identityPda,
        migrationPda,
      ]);
    } else if (typeof client.getAccountInfo === "function") {
      batch = await Promise.all([
        client.getAccountInfo(attestationPda),
        client.getAccountInfo(identityPda),
        client.getAccountInfo(migrationPda),
      ]);
    } else {
      return null;
    }

    const accountInfo = normalizeAccountInfo(batch[0]);
    const identityInfo = normalizeAccountInfo(batch[1]);
    const migrationRaw = batch[2] ?? null;
    if (!accountInfo || !identityInfo) return null;

    if (
      !ownerMatches(accountInfo.owner, sasProgram) ||
      !ownerMatches(identityInfo.owner, anchorProgram)
    ) {
      return null;
    }

    const sas = deserializeSasAttestation(accountInfo.data, nowSeconds);
    if (!sas) return null;

    const identity = deserializeIdentityStateCrossCheck(identityInfo.data);
    if (!identity) return null;

    if (sas.verifiedAt < identity.creationTimestamp) return null;

    const migration = readMigrationRecord(migrationRaw, anchorProgram);
    if (migration.status === "invalid") return null;
    if (
      migration.status === "migrated" &&
      sas.verifiedAt <= migration.migratedAt
    ) {
      return null;
    }

    return {
      ...sas,
      trustScore: Math.min(sas.trustScore, identity.trustScore),
      expired: sas.expired || identity.lastResetTimestamp > sas.verifiedAt,
    };
  } catch {
    return null;
  }
}
