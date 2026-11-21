/**
 * `@entros/verify/solana` public surface.
 *
 * Pure-MIT Solana devnet chain readers for Entros verification state, SAS
 * attestations, migration records, and 8004 Metaplex Core agent state.
 */

export {
  AGENT_REGISTRY_DEVNET_CONFIG,
  BLOCK_TIME_TOLERANCE_SECONDS,
  BN254_SCALAR_FIELD,
  CLOCK_CATCH_UP_SECONDS,
  HIGHEST_SUPPORTED_PROJECTION_VERSION,
  INTEGRATOR_DEVNET_GENESIS_HASH,
  INTEGRATOR_PROGRAM_IDS,
  RPC_TIMEOUT_MS,
  SAS_DEVNET_CONFIG,
  SOLANA_DEVNET_GENESIS_HASH,
  SOLANA_PROGRAM_IDS,
  SYSTEM_PROGRAM_ID,
} from "./constants";

export {
  addressToBase58,
  base58Decode,
  base58Encode,
  canonicalKeyBytes,
  createProgramAddressSync,
  deriveAgentAccountPda,
  deriveIdentityPda,
  deriveMigrationRecordPda,
  deriveMintPda,
  deriveProofRequestStatePda,
  deriveSasAttestationPda,
  deriveVerificationResultPda,
  equalAddress,
  findProgramAddressSync,
  isOnEd25519Curve,
  migrationRecordSeeds,
  ownerMatches,
  parseSolanaAddress,
  SolanaAddress,
} from "./address";
export type {
  AccountOwnerLike,
  AddressInput,
  Base58KeyLike,
  BytesKeyLike,
  EqualsKeyLike,
} from "./address";

export {
  boundedRpc,
  createSolanaRpcClient,
  decodeBase64,
  normalizeAccountData,
  normalizeAccountInfo,
  resolveSolanaConnection,
} from "./rpc";
export type {
  NormalizedAccountInfo,
  ParsedAccountKeyLike,
  ParsedOnlyInstructionLike,
  ParsedTransactionLike,
  PartiallyDecodedInstructionLike,
  RawAccountInfoLike,
  RpcContextResponse,
  SignatureInfoLike,
  SignatureStatusLike,
  SolanaCommitment,
  SolanaConnectionLike,
  SolanaRpcClient,
  SolanaRpcConfig,
  SolanaTransport,
  TransactionInstructionLike,
} from "./rpc";

export {
  decodeIdentityState,
  IDENTITY_STATE_DISCRIMINATOR,
  IDENTITY_STATE_LEN,
  MIGRATION_RECORD_DISCRIMINATOR,
  MIGRATION_RECORD_SIZE,
  OLDEST_PREFIX_COMPATIBLE_LEN,
  readMigrationRecord,
  SUPPORTED_IDENTITY_STATE_LENGTHS,
} from "./accounts";
export type {
  IdentityState,
  MigrationRecordAccount,
  MigrationRecordRead,
} from "./accounts";

export { commitmentHex, qualifyingTransaction } from "./transaction";
export type { IntegratorTransactionEvidence } from "./transaction";

export {
  findLatestVerificationTransaction,
  readIntegratorEvidence,
} from "./integrator";
export type {
  FindLatestVerificationTransactionInput,
  IntegratorAttestationEvidence,
  IntegratorEvidence,
  IntegratorEvidenceFailureReason,
  IntegratorEvidenceReadResult,
  IntegratorIdentityEvidence,
  ReadIntegratorEvidenceInput,
  RequestBoundDeploymentConfig,
  VerificationTransactionSearchResult,
} from "./integrator";

export { verifyEntrosAttestation } from "./sas";
export type {
  EntrosAttestation,
  VerifyEntrosAttestationOptions,
} from "./sas";

export { readAgentState } from "./agent";
export type {
  AgentStateEvidence,
  AgentStateFailureReason,
  AgentStateReadResult,
  AgentWalletStatus,
  ReadAgentStateInput,
} from "./agent";
