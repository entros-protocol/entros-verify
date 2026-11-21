import { AGENT_PERMIT_NETWORK } from "../agent-permit";
import { POLICY_NETWORK, type PolicyProgramIds } from "../policy";

/** Pinned Solana devnet genesis hash. */
export const SOLANA_DEVNET_GENESIS_HASH = POLICY_NETWORK.genesisHash;

/** Alias matching `@entros/pulse-sdk` naming for the pinned devnet genesis hash. */
export const INTEGRATOR_DEVNET_GENESIS_HASH = SOLANA_DEVNET_GENESIS_HASH;

/** Canonical Solana System Program address. */
export const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

/** Pinned Solana devnet Entros and SAS program addresses. */
export const SOLANA_PROGRAM_IDS: Readonly<PolicyProgramIds> = Object.freeze({
  anchor: POLICY_NETWORK.programIds.anchor,
  verifier: POLICY_NETWORK.programIds.verifier,
  registry: POLICY_NETWORK.programIds.registry,
  sas: POLICY_NETWORK.programIds.sas,
  credential: POLICY_NETWORK.programIds.credential,
  schema: POLICY_NETWORK.programIds.schema,
});

/** Alias matching `@entros/pulse-sdk` naming for pinned devnet program addresses. */
export const INTEGRATOR_PROGRAM_IDS = SOLANA_PROGRAM_IDS;

/** Pinned devnet Solana Attestation Service addresses for Entros. */
export const SAS_DEVNET_CONFIG = Object.freeze({
  programId: POLICY_NETWORK.programIds.sas,
  entrosCredentialPda: POLICY_NETWORK.programIds.credential,
  entrosSchemaPda: POLICY_NETWORK.programIds.schema,
});

/** Pinned devnet 8004 agent registry and Metaplex Core addresses. */
export const AGENT_REGISTRY_DEVNET_CONFIG = Object.freeze({
  programId: AGENT_PERMIT_NETWORK.agentRegistryProgram,
  coreProgramId: AGENT_PERMIT_NETWORK.coreProgram,
  collection: AGENT_PERMIT_NETWORK.agentCollection,
});

/**
 * Seconds the RPC block time of a slot may differ from the Clock sysvar time
 * the program stored in that slot.
 */
export const BLOCK_TIME_TOLERANCE_SECONDS = 2;

/**
 * Total seconds a reader waits for a local device clock that trails chain time.
 */
export const CLOCK_CATCH_UP_SECONDS = 15;

/** Highest feature-projection version accepted by the devnet reader. */
export const HIGHEST_SUPPORTED_PROJECTION_VERSION = 2;

/** BN254 scalar field prime bounding valid Poseidon commitments. */
export const BN254_SCALAR_FIELD = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/** Default per-call RPC timeout in milliseconds. */
export const RPC_TIMEOUT_MS = 3000;
