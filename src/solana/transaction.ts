import {
  type AddressInput,
  base58Decode,
  base58Encode,
  deriveProofRequestStatePda,
  deriveVerificationResultPda,
  equalAddress,
  parseSolanaAddress,
} from "./address";
import { SOLANA_PROGRAM_IDS } from "./constants";
import type {
  ParsedTransactionLike,
  PartiallyDecodedInstructionLike,
} from "./rpc";

export interface IntegratorTransactionEvidence {
  signature: string;
  slot: number;
  blockTime: number;
  commitment: string;
  kind: "mint" | "update" | "rebaseline";
}

interface DecodedAnchorInstruction {
  name:
    | "authorize_new_wallet"
    | "migrate_identity"
    | "mint_anchor"
    | "prepare_proof_request"
    | "rebaseline_anchor"
    | "reset_identity_state"
    | "set_encrypted_baseline"
    | "update_anchor"
    | "update_anchor_bound"
    | "update_anchor_compact"
    | "upgrade_identity_layout";
  expectedAccounts: number;
  commitment?: Uint8Array;
  projectionVersion?: number;
}

interface DecodedVerifierInstruction {
  name: "verify_proof" | "verify_proof_compact" | "verify_proof_bound";
  expectedAccounts: number;
  nonce: Uint8Array;
  commitmentNew: Uint8Array | null;
}

const ANCHOR_DISCRIMINATORS = Object.freeze({
  authorize_new_wallet: [178, 186, 185, 108, 51, 219, 107, 197],
  migrate_identity: [161, 192, 70, 80, 47, 37, 26, 10],
  mint_anchor: [68, 56, 113, 102, 236, 152, 146, 60],
  prepare_proof_request: [187, 40, 100, 74, 84, 21, 217, 217],
  rebaseline_anchor: [129, 211, 18, 16, 17, 54, 143, 18],
  reset_identity_state: [26, 78, 86, 143, 247, 132, 85, 203],
  set_encrypted_baseline: [10, 73, 41, 36, 2, 145, 87, 111],
  update_anchor: [120, 192, 72, 245, 112, 246, 119, 135],
  update_anchor_bound: [246, 210, 191, 60, 123, 82, 229, 214],
  update_anchor_compact: [213, 176, 229, 104, 213, 148, 253, 186],
  upgrade_identity_layout: [134, 149, 19, 29, 96, 67, 183, 14],
} as const);

const VERIFIER_DISCRIMINATORS = Object.freeze({
  verify_proof: [217, 211, 191, 110, 144, 13, 186, 98],
  verify_proof_bound: [56, 250, 245, 67, 70, 133, 5, 140],
  verify_proof_compact: [78, 42, 251, 67, 237, 19, 187, 192],
} as const);

function hasDiscriminator(
  bytes: Uint8Array,
  expected: readonly number[],
): boolean {
  if (bytes.length < 8) return false;
  for (let i = 0; i < 8; i += 1) {
    if (bytes[i] !== expected[i]) return false;
  }
  return true;
}

/** Validates an exact Borsh `UpdateReceiptArgs` tail (`i64` + `u8` + `Option<[u8; 32]>`). */
function matchesUpdateReceiptTail(bytes: Uint8Array, offset: number): boolean {
  const optionOffset = offset + 9;
  if (optionOffset >= bytes.length) return false;
  const tag = bytes[optionOffset];
  if (tag === 0) return bytes.length === optionOffset + 1;
  if (tag === 1) return bytes.length === optionOffset + 1 + 32;
  return false;
}

function decodeCanonicalBase58(data: string): Uint8Array | null {
  if (typeof data !== "string" || data.length === 0) return null;
  const bytes = base58Decode(data);
  if (!bytes || base58Encode(bytes) !== data) return null;
  return bytes;
}

function decodeAnchorInstruction(
  data: string,
): DecodedAnchorInstruction | null {
  const bytes = decodeCanonicalBase58(data);
  if (!bytes || bytes.length < 8) return null;

  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.mint_anchor)) {
    if (bytes.length !== 40) return null;
    return {
      name: "mint_anchor",
      expectedAccounts: 11,
      commitment: bytes.subarray(8, 40),
    };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.update_anchor)) {
    if (!matchesUpdateReceiptTail(bytes, 40)) return null;
    return {
      name: "update_anchor",
      expectedAccounts: 8,
      commitment: bytes.subarray(8, 40),
    };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.update_anchor_compact)) {
    if (!matchesUpdateReceiptTail(bytes, 8)) return null;
    return {
      name: "update_anchor_compact",
      expectedAccounts: 8,
    };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.update_anchor_bound)) {
    if (!matchesUpdateReceiptTail(bytes, 8)) return null;
    return {
      name: "update_anchor_bound",
      expectedAccounts: 9,
    };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.rebaseline_anchor)) {
    if (bytes.length !== 42) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return {
      name: "rebaseline_anchor",
      expectedAccounts: 6,
      commitment: bytes.subarray(8, 40),
      projectionVersion: view.getUint16(40, true),
    };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.reset_identity_state)) {
    if (bytes.length !== 42) return null;
    return { name: "reset_identity_state", expectedAccounts: 5 };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.authorize_new_wallet)) {
    if (bytes.length !== 8) return null;
    return { name: "authorize_new_wallet", expectedAccounts: 6 };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.migrate_identity)) {
    if (bytes.length !== 8) return null;
    return { name: "migrate_identity", expectedAccounts: 15 };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.prepare_proof_request)) {
    if (bytes.length !== 8) return null;
    return { name: "prepare_proof_request", expectedAccounts: 3 };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.set_encrypted_baseline)) {
    if (bytes.length !== 104) return null;
    return { name: "set_encrypted_baseline", expectedAccounts: 4 };
  }
  if (hasDiscriminator(bytes, ANCHOR_DISCRIMINATORS.upgrade_identity_layout)) {
    if (bytes.length !== 8) return null;
    return { name: "upgrade_identity_layout", expectedAccounts: 3 };
  }
  return null;
}

function decodeVerifierInstruction(
  data: string,
): DecodedVerifierInstruction | null {
  const bytes = decodeCanonicalBase58(data);
  if (!bytes || bytes.length < 8) return null;

  if (hasDiscriminator(bytes, VERIFIER_DISCRIMINATORS.verify_proof_compact)) {
    // 8 disc + 32 nonce + 256 proof + 32 new + 32 prev + 2 threshold + 2 min_distance = 364
    if (bytes.length !== 364) return null;
    return {
      name: "verify_proof_compact",
      expectedAccounts: 3,
      nonce: bytes.subarray(8, 40),
      commitmentNew: bytes.subarray(296, 328),
    };
  }
  if (hasDiscriminator(bytes, VERIFIER_DISCRIMINATORS.verify_proof_bound)) {
    // 364 + 8 valid_until = 372
    if (bytes.length !== 372) return null;
    return {
      name: "verify_proof_bound",
      expectedAccounts: 5,
      nonce: bytes.subarray(8, 40),
      commitmentNew: bytes.subarray(296, 328),
    };
  }
  if (hasDiscriminator(bytes, VERIFIER_DISCRIMINATORS.verify_proof)) {
    // 8 disc + 4 proofLen + proofLen + 4 inputsCount + inputsCount * 32 + 32 nonce
    if (bytes.length < 8 + 4 + 4 + 32) return null;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 8;
    const proofLen = view.getUint32(offset, true);
    offset += 4;
    if (offset + proofLen + 4 + 32 > bytes.length) return null;
    offset += proofLen;
    const inputsCount = view.getUint32(offset, true);
    offset += 4;
    const inputsBytes = inputsCount * 32;
    if (
      !Number.isSafeInteger(inputsBytes) ||
      offset + inputsBytes + 32 !== bytes.length
    ) {
      return null;
    }
    const firstInput =
      inputsCount >= 1 ? bytes.subarray(offset, offset + 32) : null;
    const nonceOffset = offset + inputsBytes;
    return {
      name: "verify_proof",
      expectedAccounts: 3,
      nonce: bytes.subarray(nonceOffset, nonceOffset + 32),
      commitmentNew: firstInput,
    };
  }
  return null;
}

function isPartiallyDecoded(
  instruction: unknown,
): instruction is PartiallyDecodedInstructionLike {
  return (
    typeof instruction === "object" &&
    instruction !== null &&
    "accounts" in instruction &&
    Array.isArray((instruction as PartiallyDecodedInstructionLike).accounts) &&
    typeof (instruction as PartiallyDecodedInstructionLike).data === "string"
  );
}

/** Converts a 32-byte commitment array into lowercase 64-character hex. */
export function commitmentHex(value: unknown): string | null {
  if (!(value instanceof Uint8Array) && !Array.isArray(value)) return null;
  const bytes: unknown[] = Array.from(value);
  if (
    bytes.length !== 32 ||
    !bytes.every(
      (n) => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255,
    )
  ) {
    return null;
  }
  return bytes
    .map((n) => (n as number).toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Inspects a confirmed parsed Solana transaction and extracts the unique
 * qualifying Entros verification instruction (`mint`, `update`, or `rebaseline`).
 */
export function qualifyingTransaction(
  transaction: ParsedTransactionLike,
  signature: string,
  wallet: AddressInput,
  identityPda: AddressInput,
): (IntegratorTransactionEvidence & { projectionVersion?: number }) | null {
  const walletAddr = parseSolanaAddress(wallet);
  const identityAddr = parseSolanaAddress(identityPda);
  if (!walletAddr || !identityAddr) return null;

  const instructions = transaction.transaction.message.instructions;
  if (
    !transaction.transaction.message.accountKeys.some(
      (key) => key.signer && equalAddress(key.pubkey, walletAddr),
    )
  ) {
    return null;
  }
  if (transaction.transaction.signatures[0] !== signature) return null;
  if (
    transaction.version !== undefined &&
    transaction.version !== "legacy" &&
    transaction.version !== 0
  ) {
    return null;
  }
  if (transaction.meta?.err !== null || transaction.blockTime == null) {
    return null;
  }

  const candidates: (IntegratorTransactionEvidence & {
    projectionVersion?: number;
  })[] = [];

  for (const [index, instruction] of instructions.entries()) {
    if (!equalAddress(instruction.programId, SOLANA_PROGRAM_IDS.anchor)) {
      continue;
    }
    if (!isPartiallyDecoded(instruction)) return null;
    const decoded = decodeAnchorInstruction(instruction.data);
    if (!decoded) return null;

    if (
      decoded.name !== "mint_anchor" &&
      decoded.name !== "update_anchor" &&
      decoded.name !== "update_anchor_compact" &&
      decoded.name !== "update_anchor_bound" &&
      decoded.name !== "rebaseline_anchor"
    ) {
      if (decoded.name === "reset_identity_state") return null;
      continue;
    }

    if (instruction.accounts.length !== decoded.expectedAccounts) {
      if (
        (decoded.name !== "mint_anchor" &&
          decoded.name !== "rebaseline_anchor") ||
        instruction.accounts.length !== decoded.expectedAccounts + 1
      ) {
        return null;
      }
      const [proofRequestState] = deriveProofRequestStatePda(walletAddr);
      if (
        !equalAddress(
          instruction.accounts[decoded.expectedAccounts],
          proofRequestState,
        )
      ) {
        return null;
      }
    }

    if (
      !equalAddress(instruction.accounts[0], walletAddr) ||
      !equalAddress(instruction.accounts[1], identityAddr)
    ) {
      return null;
    }

    let commitment = commitmentHex(decoded.commitment);

    if (
      decoded.name === "update_anchor_compact" ||
      decoded.name === "update_anchor_bound"
    ) {
      const bound = decoded.name === "update_anchor_bound";
      if (bound) {
        const [proofRequestState] = deriveProofRequestStatePda(walletAddr);
        if (!equalAddress(instruction.accounts[2], proofRequestState)) {
          return null;
        }
      }

      for (const earlier of instructions.slice(0, index)) {
        if (
          !equalAddress(earlier.programId, SOLANA_PROGRAM_IDS.verifier) ||
          !isPartiallyDecoded(earlier)
        ) {
          continue;
        }
        const proof = decodeVerifierInstruction(earlier.data);
        if (!proof) continue;
        if (
          bound
            ? proof.name !== "verify_proof_bound"
            : proof.name !== "verify_proof" &&
              proof.name !== "verify_proof_compact"
        ) {
          continue;
        }
        if (earlier.accounts.length !== proof.expectedAccounts) return null;

        const [verificationPda] = deriveVerificationResultPda(
          walletAddr,
          proof.nonce,
          bound,
        );
        if (
          !equalAddress(earlier.accounts[0], walletAddr) ||
          !equalAddress(earlier.accounts[1], verificationPda) ||
          !equalAddress(instruction.accounts[bound ? 3 : 2], verificationPda)
        ) {
          continue;
        }
        if (bound) {
          if (
            !equalAddress(earlier.accounts[2], identityAddr) ||
            !equalAddress(earlier.accounts[3], instruction.accounts[2])
          ) {
            return null;
          }
        }
        commitment = commitmentHex(proof.commitmentNew);
      }
    }

    if (!commitment) return null;
    candidates.push({
      signature,
      slot: transaction.slot,
      blockTime: transaction.blockTime,
      commitment,
      ...(decoded.name === "rebaseline_anchor" &&
      decoded.projectionVersion !== undefined
        ? { projectionVersion: decoded.projectionVersion }
        : {}),
      kind:
        decoded.name === "mint_anchor"
          ? "mint"
          : decoded.name === "rebaseline_anchor"
            ? "rebaseline"
            : "update",
    });
  }

  return candidates.length === 1 ? (candidates[0] ?? null) : null;
}
