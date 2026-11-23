/**
 * `@entros/verify/mcp` public surface.
 *
 * Includes MCP 2026-07-28 stateless `InputRequiredResult` (MRTR), MCP 2025-11-25
 * `SEP-1036` URL-Mode Elicitation & HTTP 403 `insufficient_scope`, OpenAI Responses
 * v2, Vercel AI SDK `toolApproval`, LiveKit/Vapi/Retell voice tool guards, atomic
 * `PermitNonceStoreV2`, and preserved v1 Solana devnet MCP adapters.
 */

// Preserved v1 exports
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

// v2 MCP, Vercel AI SDK, Voice-AI webhook guards, and atomic PermitNonceStoreV2
export {
  createInMemoryPermitNonceStoreV2,
  InMemoryPermitNonceStoreV2,
  PermitNonceStoreV2Error,
} from "./nonce-store-v2";
export type { InMemoryPermitNonceStoreV2Options } from "./nonce-store-v2";
export type {
  PermitNonceStoreV2,
  PermitNonceV2ConsumeInput,
  PermitNonceV2ConsumeResult,
  PermitNonceV2Record,
} from "../permit/types";

export {
  createStatelessMcpApprovalGate,
  signMrtrRequestState,
  verifyMrtrRequestState,
} from "./mrtr";
export type {
  McpInputRequiredResult,
  MrtrInputResponseItem,
  MrtrRequestStateClaims,
  MrtrUrlInputRequest,
  StatelessMcpApprovalGateConfig,
} from "./mrtr";

export {
  createUrlElicitationChallenge,
  DEFAULT_STEP_UP_SCOPE,
  formatInsufficientScopeHeader,
} from "./elicitation";
export type {
  InsufficientScopeHeaderOptions,
  McpUrlElicitationRequest,
  UrlElicitationChallengeInput,
} from "./elicitation";

export {
  createLiveKitToolGuard,
  createRetellWebhookGuard,
  createV2ChallengeFromOpenAiMcpRequest,
  createVapiWebhookGuard,
  createVercelToolApprovalGate,
  evaluateVoiceWebhookToolGuard,
  settleOpenAiMcpApprovalV2,
  toOpenAiMcpApprovalRequestV2,
} from "./adapters-v2";
export type {
  OpenAiMcpApprovalV2ChallengeEnvelope,
  OpenAiMcpApprovalV2SettlementEnvelope,
  RetellToolWebhookPayload,
  VapiToolCallWebhookPayload,
  VercelToolApprovalGateConfig,
  VercelToolApprovalMode,
  VoiceWebhookGuardConfig,
  VoiceWebhookGuardResult,
} from "./adapters-v2";
