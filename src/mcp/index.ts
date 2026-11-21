/**
 * `@entros/verify/mcp` public surface.
 *
 * Single-use `AgentPermit` approval adapter for Model Context Protocol servers,
 * OpenAI `mcp_approval_request` flows, and HumanLayer pause/resume callbacks.
 */

export {
  canonicalizeJson,
  canonicalizeMcpAction,
  createMcpPermitAction,
  hashMcpAction,
  McpActionValidationError,
} from "./canonical";
export type { CanonicalMcpAction, McpToolActionInput } from "./canonical";

export {
  createInMemoryNonceStore,
  InMemoryNonceStore,
  McpNonceStoreError,
} from "./nonce-store";
export type {
  InMemoryNonceStoreOptions,
  McpNonceConsumeResult,
  McpNonceRecord,
  McpNonceStore,
} from "./nonce-store";

export {
  createMcpApprovalChallenge,
  DEFAULT_MCP_APPROVAL_BASE_URL,
  DEFAULT_MCP_LIFETIME_SECONDS,
  MCP_ASSURANCE_NOTICE,
  McpApprovalError,
  verifyMcpApprovalSettlement,
} from "./approval";
export type {
  CreateMcpApprovalChallengeInput,
  McpActorIdentity,
  McpApprovalAssuranceDisclosure,
  McpApprovalChallenge,
  McpApprovalDenyReason,
  McpApprovalSettlementAllow,
  McpApprovalSettlementDeny,
  McpApprovalSettlementResult,
  McpApprovalSettlementUnavailable,
  McpApprovalUnavailableReason,
  VerifyMcpApprovalSettlementInput,
} from "./approval";

export {
  createChallengeFromOpenAiMcpRequest,
  createHumanLayerApprovalCall,
  createMcpApprovalGate,
  settleOpenAiMcpApproval,
  toOpenAiMcpApprovalRequest,
  verifyHumanLayerApprovalCallback,
} from "./adapters";
export type {
  HumanLayerApprovalCall,
  HumanLayerCallbackPayload,
  HumanLayerCallbackVerificationResult,
  HumanLayerEntrosState,
  McpApprovalGateConfig,
  OpenAiMcpApprovalChallengeEnvelope,
  OpenAiMcpApprovalRequest,
  OpenAiMcpApprovalResponse,
  OpenAiMcpApprovalSettlementEnvelope,
} from "./adapters";
