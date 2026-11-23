/**
 * `@entros/verify/voice` public surface.
 *
 * Real-time zero-retention Voice Liveness REST and WebSocket clients plus
 * offline `VoiceLivenessVerdict` JWS verification.
 */

export {
  createVoiceLivenessClient,
  sanitizeVoiceErrorDetail,
  VoiceClientError,
  VoiceLivenessClient,
} from "./client";
export type {
  AnalyzeVoiceInput,
  AnalyzeVoiceResponse,
  VoiceAudioCodec,
  VoiceClientConfig,
  VoiceClientDebugEvent,
  VoiceStreamHandle,
  VoiceStreamOptions,
  WebSocketLike,
  WebSocketLikeConstructor,
} from "./client";

export { verifyVoiceLivenessVerdict } from "./verdict";
export type {
  VerifyVoiceLivenessVerdictInput,
  VerifyVoiceLivenessVerdictReason,
  VerifyVoiceLivenessVerdictResult,
} from "./verdict";

export {
  ALL_VOICE_ABSTAIN_REASONS,
  VOICE_VERDICT_TYP,
} from "../permit/types";
export type {
  ConsistencyDrift,
  PartialSpoofSpan,
  VoiceAbstainReason,
  VoiceLivenessVerdictClaims,
  VoiceOperatingProfile,
  VoiceSignalQuality,
  VoiceVerdictDecision,
} from "../permit/types";
