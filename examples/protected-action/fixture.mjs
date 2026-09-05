import anchorPackage from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { INTEGRATOR_PROGRAM_IDS } from "@entros/pulse-sdk";
import anchorIdl from "./anchor-fixture-idl.json" with { type: "json" };
const { BN, BorshAccountsCoder, BorshInstructionCoder, utils } = anchorPackage;
const EXPECTED_DEVNET_GENESIS_HASH =
  "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

export function createEvidenceFixture({
  walletPubkey,
  nowSeconds,
  trustScore = 100,
}) {
  const wallet = new PublicKey(walletPubkey);
  const anchor = new PublicKey(INTEGRATOR_PROGRAM_IDS.anchor);
  const [identity, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("identity"), wallet.toBuffer()],
    anchor,
  );
  const [mint] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint"), wallet.toBuffer()],
    anchor,
  );
  const [attestation] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("attestation"),
      new PublicKey(INTEGRATOR_PROGRAM_IDS.credential).toBuffer(),
      new PublicKey(INTEGRATOR_PROGRAM_IDS.schema).toBuffer(),
      wallet.toBuffer(),
    ],
    new PublicKey(INTEGRATOR_PROGRAM_IDS.sas),
  );
  const signature = utils.bytes.bs58.encode(new Uint8Array(64).fill(3));
  const state = {
    trustScore,
    rpcUnavailable: false,
    identityMissing: false,
    transactionUnavailable: false,
    transactionFailed: false,
    verificationAgeSeconds: 10,
    changedCommitment: false,
    resetTimestamp: 0,
  };
  const reads = [];
  const originalCommitment = Array(32).fill(1);
  const accountCoder = new BorshAccountsCoder(anchorIdl);
  const instructionCoder = new BorshInstructionCoder(anchorIdl);
  const instruction = anchorIdl.instructions.find(
    (value) => value.name === "update_anchor",
  );
  const instructionAccounts = instruction.accounts.map((account, index) => {
    if (account.name === "authority") return wallet;
    if (account.name === "identity_state") return identity;
    if (account.name === "mint") return mint;
    return account.address
      ? new PublicKey(account.address)
      : new PublicKey(new Uint8Array(32).fill(index + 30));
  });
  const instructionData = utils.bytes.bs58.encode(
    instructionCoder.encode("update_anchor", {
      new_commitment: originalCommitment,
      verification_nonce: Array(32).fill(4),
    }),
  );
  const transaction = {
    slot: 900,
    blockTime: nowSeconds - 10,
    meta: {
      err: null,
      fee: 5000,
      preBalances: [],
      postBalances: [],
      innerInstructions: [],
      logMessages: [],
      preTokenBalances: [],
      postTokenBalances: [],
    },
    transaction: {
      signatures: [signature],
      message: {
        accountKeys: instructionAccounts.map((pubkey, index) => ({
          pubkey,
          signer: index === 0,
          writable: index < 3,
        })),
        instructions: [
          {
            programId: anchor,
            accounts: instructionAccounts,
            data: instructionData,
          },
        ],
        recentBlockhash: PublicKey.default.toBase58(),
      },
    },
    version: "legacy",
  };
  async function accountInfo() {
    const latest = nowSeconds - state.verificationAgeSeconds;
    const data = await accountCoder.encode("IdentityState", {
      owner: wallet,
      creation_timestamp: new BN(nowSeconds - 86400),
      last_verification_timestamp: new BN(latest),
      verification_count: 10,
      trust_score: state.trustScore,
      current_commitment: state.changedCommitment
        ? Array(32).fill(2)
        : originalCommitment,
      mint,
      bump,
      recent_timestamps: [
        new BN(latest),
        ...Array.from({ length: 51 }, () => new BN(0)),
      ],
      last_reset_timestamp: new BN(state.resetTimestamp),
      new_wallet: PublicKey.default,
      projection_version: 1,
      last_rebaseline_timestamp: new BN(0),
    });
    return {
      data,
      owner: anchor,
      executable: false,
      lamports: 1,
      rentEpoch: 0,
    };
  }
  const connection = {
    async getGenesisHash() {
      reads.push("genesis");
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return EXPECTED_DEVNET_GENESIS_HASH;
    },
    async getSignatureStatuses() {
      reads.push("status");
      return {
        context: { slot: 901 },
        value: [
          {
            slot: 900,
            confirmations: 1,
            err: state.transactionFailed
              ? { InstructionError: [0, "SyntheticFailure"] }
              : null,
            confirmationStatus: "confirmed",
          },
        ],
      };
    },
    async getParsedTransaction() {
      reads.push("transaction");
      return state.transactionUnavailable ? null : transaction;
    },
    async getAccountInfoAndContext(address) {
      reads.push(address.toBase58());
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      return {
        context: { slot: 901 },
        value:
          address.equals(identity) && !state.identityMissing
            ? await accountInfo()
            : null,
      };
    },
  };
  return {
    connection,
    state,
    reads,
    wallet,
    identity,
    mint,
    attestation,
    signature,
    transaction,
    accountInfo,
  };
}
