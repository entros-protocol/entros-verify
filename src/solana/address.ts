import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";

import { base58Decode, base58Encode, canonicalKeyBytes } from "../base58";
import {
  AGENT_REGISTRY_DEVNET_CONFIG,
  SAS_DEVNET_CONFIG,
  SOLANA_PROGRAM_IDS,
} from "./constants";

export { base58Decode, base58Encode, canonicalKeyBytes };

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");
const MAX_SEEDS = 16;
const MAX_SEED_LENGTH = 32;
const encoder = new TextEncoder();

export interface Base58KeyLike {
  toBase58(): string;
}

export interface BytesKeyLike {
  toBytes(): Uint8Array;
}

export interface EqualsKeyLike {
  equals(other: unknown): boolean;
}

export type AddressInput =
  | string
  | Uint8Array
  | SolanaAddress
  | Base58KeyLike
  | BytesKeyLike;

export type AccountOwnerLike =
  | AddressInput
  | (Partial<Base58KeyLike> & Partial<BytesKeyLike> & Partial<EqualsKeyLike>);

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function extractKeyBytes(input: unknown): Uint8Array | null {
  if (input instanceof SolanaAddress) {
    return input.toBytes();
  }
  if (typeof input === "string") {
    return canonicalKeyBytes(input);
  }
  if (input instanceof Uint8Array) {
    return input.length === 32 ? new Uint8Array(input) : null;
  }
  if (typeof input === "object" && input !== null) {
    const candidate = input as Record<string, unknown>;
    if (typeof candidate.toBase58 === "function") {
      try {
        const text = (candidate.toBase58 as () => unknown)();
        return typeof text === "string" ? canonicalKeyBytes(text) : null;
      } catch {
        return null;
      }
    }
    if (typeof candidate.toBytes === "function") {
      try {
        const bytes = (candidate.toBytes as () => unknown)();
        return bytes instanceof Uint8Array && bytes.length === 32
          ? new Uint8Array(bytes)
          : null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

/**
 * Lightweight Solana 32-byte address value compatible with `@solana/web3.js`
 * `PublicKey` call sites (`toBase58`, `toBytes`, `toBuffer`, `equals`).
 */
export class SolanaAddress {
  readonly #bytes: Uint8Array;
  readonly #base58: string;

  constructor(input: AddressInput) {
    const bytes = extractKeyBytes(input);
    if (!bytes) {
      throw new TypeError("Invalid Solana address");
    }
    this.#bytes = bytes;
    this.#base58 = base58Encode(bytes);
  }

  toBase58(): string {
    return this.#base58;
  }

  toString(): string {
    return this.#base58;
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.#bytes);
  }

  toBuffer(): Uint8Array {
    return new Uint8Array(this.#bytes);
  }

  equals(other: unknown): boolean {
    const otherBytes = extractKeyBytes(other);
    return otherBytes !== null && equalBytes(this.#bytes, otherBytes);
  }
}

/** Parses any canonical base58 string, 32-byte array, or PublicKey-like value. */
export function parseSolanaAddress(input: unknown): SolanaAddress | null {
  const bytes = extractKeyBytes(input);
  return bytes ? new SolanaAddress(bytes) : null;
}

/** Returns canonical base58 for a valid 32-byte address, or null. */
export function addressToBase58(input: unknown): string | null {
  const bytes = extractKeyBytes(input);
  return bytes ? base58Encode(bytes) : null;
}

/** Compares two address inputs by their 32-byte representation. */
export function equalAddress(left: unknown, right: unknown): boolean {
  const a = extractKeyBytes(left);
  const b = extractKeyBytes(right);
  return a !== null && b !== null && equalBytes(a, b);
}

/**
 * Checks whether an account owner field matches an expected program address.
 * Supports strings, 32-byte arrays, `SolanaAddress`, `PublicKey`, and minimal
 * `{ equals }` test doubles.
 */
export function ownerMatches(
  owner: unknown,
  expected: AddressInput,
): boolean {
  const target = parseSolanaAddress(expected);
  if (!target || owner === undefined || owner === null) return false;
  const ownerBytes = extractKeyBytes(owner);
  if (ownerBytes !== null) {
    return equalBytes(ownerBytes, target.toBytes());
  }
  if (
    typeof owner === "object" &&
    typeof (owner as EqualsKeyLike).equals === "function"
  ) {
    try {
      return (
        (owner as EqualsKeyLike).equals(expected) === true ||
        (owner as EqualsKeyLike).equals(target) === true
      );
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Returns true when 32 bytes decode to a point on the Ed25519 curve under
 * RFC 8032 decompression rules, matching Solana's `Pubkey::is_on_curve`.
 */
export function isOnEd25519Curve(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false;
  try {
    ed25519.Point.fromBytes(bytes, false);
    return true;
  } catch {
    return false;
  }
}

/**
 * Derives a Solana program address for fixed seeds without searching for a bump.
 * Throws when seed limits are violated or the resulting digest lies on Ed25519.
 */
export function createProgramAddressSync(
  seeds: readonly Uint8Array[],
  programId: AddressInput,
): string {
  if (seeds.length > MAX_SEEDS) {
    throw new TypeError("Max seed count exceeded");
  }
  const program = parseSolanaAddress(programId);
  if (!program) {
    throw new TypeError("Invalid program address");
  }
  const programBytes = program.toBytes();
  let totalLength = programBytes.length + PDA_MARKER.length;
  for (const seed of seeds) {
    if (seed.length > MAX_SEED_LENGTH) {
      throw new TypeError("Max seed length exceeded");
    }
    totalLength += seed.length;
  }
  const preimage = new Uint8Array(totalLength);
  let offset = 0;
  for (const seed of seeds) {
    preimage.set(seed, offset);
    offset += seed.length;
  }
  preimage.set(programBytes, offset);
  offset += programBytes.length;
  preimage.set(PDA_MARKER, offset);

  const hash = sha256(preimage);
  if (isOnEd25519Curve(hash)) {
    throw new Error("Invalid seeds, address must fall off the curve");
  }
  return base58Encode(hash);
}

/**
 * Finds the canonical Solana PDA and bump seed in `[255..0]` for `seeds` and `programId`.
 */
export function findProgramAddressSync(
  seeds: readonly Uint8Array[],
  programId: AddressInput,
): [string, number] {
  if (seeds.length >= MAX_SEEDS) {
    throw new TypeError("Max seed count exceeded");
  }
  const program = parseSolanaAddress(programId);
  if (!program) {
    throw new TypeError("Invalid program address");
  }
  for (let bump = 255; bump >= 0; bump -= 1) {
    try {
      const address = createProgramAddressSync(
        [...seeds, Uint8Array.of(bump)],
        program,
      );
      return [address, bump];
    } catch (error) {
      if (error instanceof TypeError) throw error;
    }
  }
  throw new Error("Unable to find a viable program address nonce");
}

/** Seeds for a wallet's migration record under the Entros Anchor program. */
export function migrationRecordSeeds(wallet: AddressInput): Uint8Array[] {
  const addr = parseSolanaAddress(wallet);
  if (!addr) throw new TypeError("Invalid wallet address");
  return [encoder.encode("migration"), addr.toBytes()];
}

/** Derives a wallet's `IdentityState` PDA under the Entros Anchor program. */
export function deriveIdentityPda(
  wallet: AddressInput,
  anchorProgram: AddressInput = SOLANA_PROGRAM_IDS.anchor,
): [string, number] {
  const addr = parseSolanaAddress(wallet);
  if (!addr) throw new TypeError("Invalid wallet address");
  return findProgramAddressSync(
    [encoder.encode("identity"), addr.toBytes()],
    anchorProgram,
  );
}

/** Derives a wallet's NonTransferable Anchor mint PDA. */
export function deriveMintPda(
  wallet: AddressInput,
  anchorProgram: AddressInput = SOLANA_PROGRAM_IDS.anchor,
): [string, number] {
  const addr = parseSolanaAddress(wallet);
  if (!addr) throw new TypeError("Invalid wallet address");
  return findProgramAddressSync(
    [encoder.encode("mint"), addr.toBytes()],
    anchorProgram,
  );
}

/** Derives a wallet's `MigrationRecord` PDA under the Entros Anchor program. */
export function deriveMigrationRecordPda(
  wallet: AddressInput,
  anchorProgram: AddressInput = SOLANA_PROGRAM_IDS.anchor,
): [string, number] {
  return findProgramAddressSync(migrationRecordSeeds(wallet), anchorProgram);
}

/** Derives a wallet's `ProofRequestState` PDA under the Entros Anchor program. */
export function deriveProofRequestStatePda(
  wallet: AddressInput,
  anchorProgram: AddressInput = SOLANA_PROGRAM_IDS.anchor,
): [string, number] {
  const addr = parseSolanaAddress(wallet);
  if (!addr) throw new TypeError("Invalid wallet address");
  return findProgramAddressSync(
    [encoder.encode("proof_request_state"), addr.toBytes()],
    anchorProgram,
  );
}

/** Derives a wallet's Entros SAS attestation PDA. */
export function deriveSasAttestationPda(
  wallet: AddressInput,
  config?: {
    programId?: AddressInput;
    credential?: AddressInput;
    schema?: AddressInput;
  },
): [string, number] {
  const walletAddr = parseSolanaAddress(wallet);
  const credentialAddr = parseSolanaAddress(
    config?.credential ?? SAS_DEVNET_CONFIG.entrosCredentialPda,
  );
  const schemaAddr = parseSolanaAddress(
    config?.schema ?? SAS_DEVNET_CONFIG.entrosSchemaPda,
  );
  if (!walletAddr || !credentialAddr || !schemaAddr) {
    throw new TypeError("Invalid SAS PDA address input");
  }
  return findProgramAddressSync(
    [
      encoder.encode("attestation"),
      credentialAddr.toBytes(),
      schemaAddr.toBytes(),
      walletAddr.toBytes(),
    ],
    config?.programId ?? SAS_DEVNET_CONFIG.programId,
  );
}

/** Derives a verifier `VerificationResult` or `BoundVerificationResult` PDA. */
export function deriveVerificationResultPda(
  wallet: AddressInput,
  nonce: Uint8Array,
  bound = false,
  verifierProgram: AddressInput = SOLANA_PROGRAM_IDS.verifier,
): [string, number] {
  const walletAddr = parseSolanaAddress(wallet);
  if (!walletAddr || nonce.length !== 32) {
    throw new TypeError("Invalid verification result PDA input");
  }
  return findProgramAddressSync(
    [
      encoder.encode(bound ? "verification_bound" : "verification"),
      walletAddr.toBytes(),
      nonce,
    ],
    verifierProgram,
  );
}

/** Derives an 8004 registry `AgentAccount` PDA from its Metaplex Core asset address. */
export function deriveAgentAccountPda(
  agent: AddressInput,
  agentRegistryProgram: AddressInput = AGENT_REGISTRY_DEVNET_CONFIG.programId,
): [string, number] {
  const asset = parseSolanaAddress(agent);
  if (!asset) throw new TypeError("Invalid agent asset address");
  return findProgramAddressSync(
    [encoder.encode("agent"), asset.toBytes()],
    agentRegistryProgram,
  );
}
