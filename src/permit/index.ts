/**
 * `@entros/verify/permit` public surface.
 *
 * Pure-MIT Entros-Agent-Permit-v2 verification, RFC 8785 JCS canonicalization,
 * Policy v2 evaluation, zero-CBOR WebAuthn P-256 verification (`lowS: false`),
 * RFC 9449 DPoP verification, zero-dependency IETF SCITT COSE_Sign1 verification,
 * Ed25519 JWKS cache, and `/v1/permits/*` API client.
 */

export {
  AGENT_PERMIT_V2_DOMAIN,
  AGENT_PERMIT_V2_TYP,
  ALL_ASSURANCE_TIERS_V2,
  ALL_VOICE_ABSTAIN_REASONS,
  PERMIT_V2_LIMITS,
  VOICE_VERDICT_TYP,
  WEBAUTHN_ASSERTION_V2_DOMAIN,
  WEBAUTHN_CHALLENGE_V2_DOMAIN,
} from "./types";
export type {
  ActionKindV2,
  AgentPermitV2Claims,
  AssuranceTierV2,
  CanonicalActionV2Input,
  CanonicalActionV2Result,
  ConsistencyDrift,
  ContinuityModeV2,
  DpopVerifyOptions,
  DpopVerifyResult,
  EcP256Jwk,
  Ed25519Jwk,
  JwkLookupResult,
  JwksDocument,
  JwksResolver,
  JwksSource,
  PartialSpoofSpan,
  PermitActorV2,
  PermitCnfV2,
  PermitContinuityV2,
  PermitNonceStoreV2,
  PermitNonceV2ConsumeInput,
  PermitNonceV2ConsumeResult,
  PermitNonceV2Record,
  PermitV2DenyCode,
  PermitV2RefusalCode,
  PermitV2UnavailableCode,
  PolicyV2,
  ScittDecisionStatement,
  ScittVerificationResult,
  UniquenessRequirementV2,
  UniquenessStatusV2,
  VerifiedScittReceipt,
  VerifyAgentPermitV2Input,
  VerifyAgentPermitV2Result,
  VoiceAbstainReason,
  VoiceLivenessVerdictClaims,
  VoiceOperatingProfile,
  VoicePolicyRulesV2,
  VoiceSignalQuality,
  VoiceVerdictDecision,
  WebAuthnAssertionInput,
  WebAuthnVerifyOptions,
  WebAuthnVerifyResult,
} from "./types";

export {
  canonicalizeJcs,
  CanonicalJsonError,
  hashActionV2,
  parseStrictJson,
  validateActionV2,
} from "./canonical";
export type { CanonicalJsonErrorCode } from "./canonical";

export {
  base64UrlDecodeStrict,
  base64UrlEncode,
  bytesToHex,
  constantTimeEqual,
  constantTimeEqualString,
  hexToBytes,
  isCanonicalAudUri,
  isStrictHttpsOrLoopbackUri,
} from "./encoding";

export {
  createJwksCache,
  createStaticJwksResolver,
  isEd25519Jwk,
  JwksCache,
  normalizeJwksSource,
} from "./jwks";
export type { JwksCacheOptions } from "./jwks";

export {
  parseCompactJws,
  verifyEdDsaJws,
  verifyStrictEd25519Signature,
} from "./jws";
export type { ParsedCompactJws, VerifyEdDsaJwsResult } from "./jws";

export {
  computeWebAuthnAssertionDigestV2,
  deriveWebAuthnChallengeV2,
  parseAuthenticatorData,
  verifyWebAuthnAssertionV2,
} from "./webauthn";
export type {
  DerivedWebAuthnChallenge,
  ParsedAuthenticatorData,
} from "./webauthn";

export {
  computeJwkThumbprint,
  normalizeDpopHtu,
  verifyDpopProofV2,
} from "./dpop";

export { decodeDefiniteCbor, verifyScittReceipt } from "./scitt";
export type {
  CborMap,
  CborTagged,
  CborValue,
  VerifyScittReceiptOptions,
} from "./scitt";

export {
  evaluatePolicyV2,
  parseAgentPermitV2Claims,
  verifyAgentPermitV2,
} from "./policy";
export type { EvaluatePolicyV2Input, EvaluatePolicyV2Result } from "./policy";

export {
  createPermitApiClient,
  PermitApiClient,
  PermitApiError,
} from "./client";
export type {
  CreateStepUpRequestV2,
  CreateStepUpResponseV2,
  FetchScittReceiptResponseV2,
  IssuePermitRequestV2,
  IssuePermitResponseV2,
  PermitApiClientConfig,
  StepUpModeV2,
  VerifyPermitOnlineRequestV2,
  VerifyPermitOnlineResponseV2,
} from "./client";
