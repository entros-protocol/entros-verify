import anchorPackage from "@coral-xyz/anchor";
import { PublicKey } from "@solana/web3.js";
import { INTEGRATOR_PROGRAM_IDS } from "@entros/pulse-sdk";
import { AGENT_PERMIT_NETWORK } from "@entros/verify/agent-permit";
import anchorIdl from "./anchor-fixture-idl.json" with { type: "json" };

const { BN, BorshAccountsCoder, BorshInstructionCoder, utils } = anchorPackage;
const AGENT_ACCOUNT_DISCRIMINATOR = Buffer.from("f177458ce9097032", "hex");
const REGISTRY = new PublicKey(AGENT_PERMIT_NETWORK.agentRegistryProgram);
const CORE = new PublicKey(AGENT_PERMIT_NETWORK.coreProgram);
const COLLECTION = new PublicKey(AGENT_PERMIT_NETWORK.agentCollection);

/** Core `AssetV1` bytes with a collection update authority and no plugins. */
function coreAsset(owner, collection = COLLECTION) {
  const name = Buffer.from("Agent");
  const uri = Buffer.from("ipfs://synthetic-agent");
  const data = Buffer.alloc(1 + 32 + 1 + 32 + 4 + name.length + 4 + uri.length + 1);
  let offset = 0;
  data[offset++] = 1;
  owner.toBuffer().copy(data, offset);
  offset += 32;
  data[offset++] = 2;
  collection.toBuffer().copy(data, offset);
  offset += 32;
  data.writeUInt32LE(name.length, offset);
  name.copy(data, offset + 4);
  offset += 4 + name.length;
  data.writeUInt32LE(uri.length, offset);
  uri.copy(data, offset + 4);
  offset += 4 + uri.length;
  data[offset] = 0;
  return data;
}

/** Registry `AgentAccount` prefix, padded to its fixed 748 bytes. */
function agentAccount(asset, bump, cachedOwner, agentWallet) {
  const data = Buffer.alloc(748);
  AGENT_ACCOUNT_DISCRIMINATOR.copy(data, 0);
  COLLECTION.toBuffer().copy(data, 8);
  cachedOwner.toBuffer().copy(data, 40);
  cachedOwner.toBuffer().copy(data, 72);
  asset.toBuffer().copy(data, 104);
  data[136] = bump;
  data[137] = 0;
  data[138] = agentWallet ? 1 : 0;
  if (agentWallet) agentWallet.toBuffer().copy(data, 139);
  return data;
}

/**
 * Synthetic devnet state for one agent and any number of operator wallets. The connection
 * answers the reads that `readAgentState` and `readIntegratorEvidence` make.
 */
export function createChainFixture({ agent, owner, nowSeconds }) {
  const asset = new PublicKey(agent);
  const [agentAccountAddress, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("agent"), asset.toBuffer()],
    REGISTRY,
  );
  const anchor = new PublicKey(INTEGRATOR_PROGRAM_IDS.anchor);
  const accountCoder = new BorshAccountsCoder(anchorIdl);
  const instructionCoder = new BorshInstructionCoder(anchorIdl);
  const updateAnchor = anchorIdl.instructions.find((value) => value.name === "update_anchor");
  const state = {
    coreOwner: new PublicKey(owner),
    cachedOwner: new PublicKey(owner),
    agentWallet: null,
    collection: COLLECTION,
    burned: false,
    rpcUnavailable: false,
    slot: 900,
  };
  const reads = [];
  const operators = new Map();

  function operatorRecord(walletPubkey) {
    const existing = operators.get(walletPubkey);
    if (existing) return existing;
    const wallet = new PublicKey(walletPubkey);
    const [identity, identityBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("identity"), wallet.toBuffer()],
      anchor,
    );
    const [mint] = PublicKey.findProgramAddressSync([Buffer.from("mint"), wallet.toBuffer()], anchor);
    const commitment = Array(32).fill(operators.size + 1);
    const signature = utils.bytes.bs58.encode(new Uint8Array(64).fill(operators.size + 3));
    const accounts = updateAnchor.accounts.map((account, index) => {
      if (account.name === "authority") return wallet;
      if (account.name === "identity_state") return identity;
      if (account.name === "mint") return mint;
      return account.address
        ? new PublicKey(account.address)
        : new PublicKey(new Uint8Array(32).fill(index + 30));
    });
    const transaction = {
      slot: 890,
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
          accountKeys: accounts.map((pubkey, index) => ({
            pubkey,
            signer: index === 0,
            writable: index < 3,
          })),
          instructions: [
            {
              programId: anchor,
              accounts,
              data: utils.bytes.bs58.encode(
                instructionCoder.encode("update_anchor", {
                  new_commitment: commitment,
                  verification_nonce: Array(32).fill(4),
                }),
              ),
            },
          ],
          recentBlockhash: PublicKey.default.toBase58(),
        },
      },
      version: "legacy",
    };
    const record = {
      wallet,
      identity,
      identityBump,
      mint,
      commitment,
      signature,
      transaction,
      trustScore: 250,
      verificationAgeSeconds: 10,
      identityMissing: false,
    };
    operators.set(walletPubkey, record);
    return record;
  }
  operatorRecord(owner);

  async function identityAccount(record) {
    const latest = nowSeconds - record.verificationAgeSeconds;
    return {
      data: await accountCoder.encode("IdentityState", {
        owner: record.wallet,
        creation_timestamp: new BN(nowSeconds - 86400),
        last_verification_timestamp: new BN(latest),
        verification_count: 10,
        trust_score: record.trustScore,
        current_commitment: record.commitment,
        mint: record.mint,
        bump: record.identityBump,
        recent_timestamps: [new BN(latest), ...Array.from({ length: 51 }, () => new BN(0))],
        last_reset_timestamp: new BN(0),
        new_wallet: PublicKey.default,
        projection_version: 1,
        last_rebaseline_timestamp: new BN(0),
      }),
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
      return AGENT_PERMIT_NETWORK.genesisHash;
    },
    async getMultipleAccountsInfoAndContext(keys) {
      reads.push(`accounts:${keys.map((key) => key.toBase58()).join(",")}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      const value = keys.map((key) => {
        if (key.equals(asset)) {
          return {
            data: state.burned ? Buffer.from([0]) : coreAsset(state.coreOwner, state.collection),
            owner: CORE,
            executable: false,
            lamports: 1,
            rentEpoch: 0,
          };
        }
        if (key.equals(agentAccountAddress)) {
          return {
            data: agentAccount(asset, bump, state.cachedOwner, state.agentWallet),
            owner: REGISTRY,
            executable: false,
            lamports: 1,
            rentEpoch: 0,
          };
        }
        return null;
      });
      return { context: { slot: state.slot }, value };
    },
    async getSignatureStatuses([signature]) {
      reads.push("status");
      const known = [...operators.values()].some((record) => record.signature === signature);
      return {
        context: { slot: state.slot },
        value: [known ? { slot: 890, confirmations: 1, err: null, confirmationStatus: "confirmed" } : null],
      };
    },
    async getParsedTransaction(signature) {
      reads.push("transaction");
      const record = [...operators.values()].find((entry) => entry.signature === signature);
      if (!record) return null;
      // The verification transaction ages with the identity it updated.
      return { ...record.transaction, blockTime: nowSeconds - record.verificationAgeSeconds };
    },
    async getAccountInfoAndContext(address) {
      reads.push(`account:${address.toBase58()}`);
      if (state.rpcUnavailable) throw new Error("Synthetic RPC unavailable");
      const record = [...operators.values()].find((entry) => entry.identity.equals(address));
      return {
        context: { slot: state.slot },
        value: record && !record.identityMissing ? await identityAccount(record) : null,
      };
    },
  };

  return {
    connection,
    reads,
    state,
    agentAccount: agentAccountAddress.toBase58(),
    operator: operatorRecord,
    /** The owner binds an agent wallet through `set_agent_wallet`, which also syncs the cache. */
    bind(agentWallet) {
      state.agentWallet = new PublicKey(agentWallet);
      state.cachedOwner = state.coreOwner;
      state.slot += 1;
    },
    /** A Metaplex Core transfer outside the registry leaves the registry cache stale. */
    transferDirect(newOwner) {
      state.coreOwner = new PublicKey(newOwner);
      state.slot += 1;
    },
    /** The registry's `transfer_agent` moves the asset, syncs the cache and resets the wallet. */
    transferThroughRegistry(newOwner) {
      state.coreOwner = new PublicKey(newOwner);
      state.cachedOwner = state.coreOwner;
      state.agentWallet = null;
      state.slot += 1;
    },
  };
}
