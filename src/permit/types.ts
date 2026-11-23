/**
 * Canonical protocol types for Entros-Agent-Permit-v2, VoiceLivenessVerdict,
 * Policy v2, WebAuthn UV, DPoP, and IETF SCITT receipts.
 */

export const AGENT_PERMIT_V2_DOMAIN = "Entros-Agent-Permit-v2";
export const WEBAUTHN_CHALLENGE_V2_DOMAIN = "Entros-WebAuthn-Challenge-v2";
export const WEBAUTHN_ASSERTION_V2_DOMAIN = "Entros-WebAuthn-Assertion-v2";
export const VOICE_VERDICT_TYP = "entros-voice-liveness+jwt";
export const AGENT_PERMIT_V2_TYP = "entros-agent-permit+jwt";

export const PERMIT_V2_LIMITS = Object.freeze({
  minLifetimeSeconds: 30,
  maxLifetimeSeconds: 900,
  voiceMinLifetimeSeconds: 30,
  voiceMaxLifetimeSeconds: 300,
  clockSkewSeconds: 30,
  maxUriLength: 200,
  maxIdentifierLength: 128,
  maxSubjectLength: 256,
  minTimeSeconds: 946684800,
  maxTimeSeconds: 253402300799,
  maxJwksTtlSeconds: 300,
  minNegativeCacheSeconds: 10,
  maxCanonicalDepth: 32,
} as const);

export const ALL_ASSURANCE_TIERS_V2 = Object.freeze([
  "voice_liveness_webrtc",
  "voice_liveness_telephony",
  "passkey_webauthn_uv",
  "voice_plus_passkey",
  "passive_browser_risk",
  "hardware_attested_mobile",
  "browser_unattested",
] as const);

export type AssuranceTierV2 = (typeof ALL_ASSURANCE_TIERS_V2)[number];

export const ALL_VOICE_ABSTAIN_REASONS = Object.freeze([
  "silence",
  "short_speech",
  "low_snr",
  "clipping",
  "unsupported_codec",
  "packet_loss",
  "ensemble_disagreement",
  "inference_unavailable",
] as const);

export type VoiceAbstainReason = (typeof ALL_VOICE_ABSTAIN_REASONS)[number];

export type VoiceVerdictDecision =
  | "likely_human"
  | "suspicious"
  | "likely_synthetic"
  | "insufficient_signal";

export type VoiceOperatingProfile =
  | "webrtc_16k"
  | "telephony_8k"
  | "wideband_clean";

export interface VoiceSignalQuality {
  snr_db: number;
  speech_ms: number;
  clipping: number;
  codec_bandwidth_hz: number;
}

export interface PartialSpoofSpan {
  start_ms: number;
  end_ms: number;
  spoof_probability: number;
}

export interface ConsistencyDrift {
  status: "evaluated" | "elevated" | "not_applicable";
  windows_evaluated: number;
  floor_spread_db: number | null;
  tail_decay_spread_db: number | null;
  spectral_tilt_drift: number | null;
  reason: string | null;
}

export interface VoiceLivenessVerdictClaims {
  iss: string;
  jti: string;
  iat: number;
  exp: number;
  session_id: string;
  verdict: VoiceVerdictDecision;
  calibrated_llr: number | null;
  operating_profile: VoiceOperatingProfile;
  model_version: string;
  signal_quality: VoiceSignalQuality;
  partial_spoof_spans: PartialSpoofSpan[];
  consistency_drift: ConsistencyDrift;
  abstain_reason: VoiceAbstainReason | null;
  retention: "memory_only";
}

export type UniquenessStatusV2 =
  | "unmeasured"
  | "session_bound"
  | "enterprise_idp_subject";

export type ContinuityModeV2 = "call_session" | "step_up_only" | "stateless";

export interface PermitActorV2 {
  id: string;
  client_id?: string;
  key_jkt?: string;
  act?: Record<string, unknown>;
}

export interface PermitContinuityV2 {
  session_id: string;
  mode: ContinuityModeV2;
  call_continuity_verified?: boolean;
  step_up_triggered?: boolean;
  prior_permit_jti?: string | null;
}

export interface PermitCnfV2 {
  jkt: string;
}

export interface AgentPermitV2Claims {
  iss: string;
  sub: string;
  actor: PermitActorV2;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
  request_digest: string;
  assurance_tier: AssuranceTierV2;
  modality: string[];
  freshness_verified_at: number;
  continuity: PermitContinuityV2;
  uniqueness_status: UniquenessStatusV2;
  voice_verdict_jws: string | null;
  webauthn_assertion_digest: string | null;
  policy_id: string;
  scitt_receipt: string | null;
  cnf?: PermitCnfV2;
  authorization_details?: unknown[];
  txn?: string;
}

export type ActionKindV2 = "mcp.tool_call" | "voice.tool_call" | "http.action";

export interface CanonicalActionV2Input {
  kind: ActionKindV2;
  server: string;
  tool: string;
  arguments: Record<string, unknown>;
  rar_details?: unknown[];
}

export interface CanonicalActionV2Result {
  action: CanonicalActionV2Input;
  canonicalJson: string;
  requestDigest: string;
}

export interface VoicePolicyRulesV2 {
  allowed_profiles: VoiceOperatingProfile[];
  allowed_verdicts?: VoiceVerdictDecision[];
  min_calibrated_llr?: number;
  min_speech_ms?: number;
  min_snr_db?: number;
  max_voice_age_seconds?: number;
  max_partial_spoof_spans?: number;
  max_partial_spoof_probability?: number;
  reject_on_abstain?: boolean;
  reject_on_consistency_drift?: boolean;
  allowed_model_versions?: string[];
}

export type UniquenessRequirementV2 =
  | "allow_unmeasured"
  | "require_session_bound"
  | "require_enterprise_idp_subject";

export interface PolicyV2 {
  policy_id: string;
  version: 2;
  allowed_assurance_tiers: AssuranceTierV2[];
  required_modalities: string[];
  max_evidence_age_seconds: number;
  max_permit_lifetime_seconds: number;
  require_continuity: boolean;
  require_dpop: boolean;
  require_scitt_receipt: boolean;
  uniqueness_requirement?: UniquenessRequirementV2;
  voice_rules?: VoicePolicyRulesV2;
}

export type PermitV2DenyCode =
  | "invalid_jws"
  | "unsupported_alg"
  | "invalid_typ"
  | "unknown_kid"
  | "revoked_kid"
  | "invalid_signature"
  | "invalid_permit"
  | "lifetime_exceeded"
  | "clock_skew_exceeded"
  | "permit_expired"
  | "audience_mismatch"
  | "request_digest_mismatch"
  | "policy_mismatch"
  | "assurance_downgrade"
  | "modality_missing"
  | "freshness_regression"
  | "evidence_stale"
  | "continuity_broken"
  | "voice_verdict_invalid"
  | "voice_retention_violation"
  | "voice_profile_disallowed"
  | "voice_verdict_not_allowed"
  | "partial_spoof_detected"
  | "consistency_drift_exceeded"
  | "webauthn_assertion_invalid"
  | "webauthn_uv_required"
  | "dpop_proof_invalid"
  | "scitt_receipt_invalid"
  | "nonce_not_found"
  | "nonce_replayed";

export type PermitV2UnavailableCode = "state_unavailable";

export type PermitV2RefusalCode = PermitV2DenyCode | PermitV2UnavailableCode;

export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  use?: "sig";
  alg?: "EdDSA";
  kid: string;
  x: string;
  status?: "active" | "retiring" | "revoked" | string;
}

export interface JwksDocument {
  keys: Ed25519Jwk[];
}

export type JwkLookupResult =
  | { status: "found"; kid: string; publicKey: Uint8Array }
  | { status: "revoked"; kid: string }
  | { status: "unknown"; kid: string }
  | { status: "unavailable"; detail: string };

export interface JwksResolver {
  resolveEd25519Key(kid: string): Promise<JwkLookupResult> | JwkLookupResult;
}

export type JwksSource = JwksDocument | JwksResolver;

export interface EcP256Jwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

export interface WebAuthnAssertionInput {
  credential_id: string | Uint8Array;
  authenticator_data: string | Uint8Array;
  client_data_json: string | Uint8Array;
  signature: string | Uint8Array;
}

export interface WebAuthnVerifyOptions {
  assertion: WebAuthnAssertionInput;
  publicKey: Uint8Array | string | EcP256Jwk;
  expectedRpId: string;
  expectedOrigin: string;
  expectedChallenge: string | Uint8Array;
  storedSignCount?: number;
  allowCrossOrigin?: boolean;
}

export type WebAuthnVerifyResult =
  | {
      ok: true;
      assertionDigest: string;
      signCount: number;
      userPresent: true;
      userVerified: true;
      rpIdHashHex: string;
    }
  | {
      ok: false;
      reason: "webauthn_assertion_invalid" | "webauthn_uv_required";
      detail: string;
    };

export interface DpopVerifyOptions {
  proof: string;
  expectedJkt: string;
  expectedHtm: string;
  expectedHtu: string;
  permitJws: string;
  nowSeconds: number;
  maxAgeSeconds?: number;
}

export type DpopVerifyResult =
  | {
      ok: true;
      jkt: string;
      jti: string;
      iat: number;
      htm: string;
      htu: string;
      ath: string;
    }
  | {
      ok: false;
      reason: "dpop_proof_invalid";
      detail: string;
    };

export interface ScittDecisionStatement {
  schema: "entros-scitt-permit-v2";
  jti: string;
  request_digest: string;
  policy_id: string;
  aud: string;
  decision: "allow" | "deny";
  reason: string;
  assurance_tier: AssuranceTierV2;
  modality: string[];
  freshness_verified_at: number;
  evaluated_at: number;
  model_version: string | null;
  retention: "memory_only";
}

export interface VerifiedScittReceipt {
  kid: string;
  vds: 1;
  treeSize: number;
  leafIndex: number;
  leafHashHex: string;
  merkleRootHex: string;
  statement: ScittDecisionStatement;
}

export type ScittVerificationResult =
  | { ok: true; receipt: VerifiedScittReceipt }
  | {
      ok: false;
      reason: "scitt_receipt_invalid" | "state_unavailable";
      detail: string;
    };

export interface PermitNonceV2Record {
  jti: string;
  requestDigest: string;
  aud: string;
  policyId?: string;
  createdAt: number;
  expiresAt: number;
  consumedAt: number | null;
}

export type PermitNonceV2ConsumeResult =
  | { status: "consumed"; record: PermitNonceV2Record }
  | { status: "not_found" }
  | { status: "already_consumed"; consumedAt: number }
  | { status: "expired" };

export interface PermitNonceV2ConsumeInput {
  jti: string;
  requestDigest: string;
  aud: string;
  policyId?: string;
  expiresAt: number;
  nowSeconds: number;
  /** When true, require prior `register()` before consuming. Default false (stateless replay guard). */
  requireRegistered?: boolean;
}

export interface PermitNonceStoreV2 {
  register(record: {
    jti: string;
    requestDigest: string;
    aud: string;
    policyId?: string;
    issuedAt: number;
    expiresAt: number;
  }): Promise<void> | void;
  peek(jti: string): Promise<PermitNonceV2Record | null> | PermitNonceV2Record | null;
  consume(
    input: PermitNonceV2ConsumeInput,
  ): Promise<PermitNonceV2ConsumeResult> | PermitNonceV2ConsumeResult;
}

export interface VerifyAgentPermitV2Input {
  permitJws: string;
  policy: PolicyV2;
  expectedAudience: string;
  action?: CanonicalActionV2Input;
  expectedRequestDigest?: string;
  jwks: JwksSource;
  voiceJwks?: JwksSource;
  scittJwks?: JwksSource;
  revokedKids?: ReadonlySet<string> | readonly string[];
  nowSeconds?: number | (() => number);
  webauthn?: Omit<WebAuthnVerifyOptions, "expectedChallenge">;
  dpop?: {
    proof: string;
    htm: string;
    htu: string;
    maxAgeSeconds?: number;
  };
  nonceStore?: PermitNonceStoreV2;
  requireRegisteredNonce?: boolean;
}

export type VerifyAgentPermitV2Result =
  | {
      decision: "allow";
      reason: "accepted";
      permit: AgentPermitV2Claims;
      voiceVerdict: VoiceLivenessVerdictClaims | null;
      webauthn: Extract<WebAuthnVerifyResult, { ok: true }> | null;
      dpop: Extract<DpopVerifyResult, { ok: true }> | null;
      scittReceipt: VerifiedScittReceipt | null;
      evaluatedAt: number;
    }
  | {
      decision: "deny";
      reason: PermitV2DenyCode;
      detail?: string;
      permit: AgentPermitV2Claims | null;
      evaluatedAt: number;
    }
  | {
      decision: "unavailable";
      reason: PermitV2UnavailableCode;
      detail?: string;
      permit: AgentPermitV2Claims | null;
      evaluatedAt: number;
    };
