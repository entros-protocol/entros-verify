/**
 * Voice Liveness REST (`POST /v1/voice/analyze`) and WebSocket streaming
 * (`GET /v1/voice/stream`) clients supporting PCM16 (16 kHz), Opus (16/48 kHz),
 * and G.711 mu-law (8 kHz).
 *
 * Raw audio bytes and Base64 audio payloads are never emitted in errors or
 * debug callbacks.
 */

import {
  base64UrlEncode,
  decodeUtf8Strict,
  isPlainRecord,
  isStrictHttpsOrLoopbackUri,
} from "../permit/encoding";
import type {
  JwksSource,
  VoiceLivenessVerdictClaims,
  VoiceOperatingProfile,
} from "../permit/types";
import { verifyVoiceLivenessVerdict } from "./verdict";

export type VoiceAudioCodec =
  | "pcm16_16k"
  | "opus_16k"
  | "opus_48k"
  | "mulaw_8k";

export interface VoiceClientConfig {
  /** Base HTTPS URI (or http://127.0.0.1 for local loopback tests). */
  baseUrl: string;
  /** Optional Bearer API key for hosted or VPC firewall API authentication. */
  apiKey?: string;
  /** Optional custom fetch implementation. */
  fetch?: typeof globalThis.fetch;
  /** Optional WebSocket constructor override for non-global runtimes or tests. */
  webSocketCtor?: WebSocketLikeConstructor;
  /** Default REST request timeout in milliseconds. Default 10,000. */
  timeoutMs?: number;
  /** Optional metadata-only debug hook (never receives audio bytes or base64). */
  onDebug?: (event: VoiceClientDebugEvent) => void;
}

export interface VoiceClientDebugEvent {
  type: "analyze_request" | "analyze_response" | "stream_open" | "stream_frame" | "stream_verdict" | "stream_close" | "error";
  sessionId?: string;
  codec?: VoiceAudioCodec;
  byteLength?: number;
  status?: number;
  verdict?: string;
  message?: string;
}

export interface AnalyzeVoiceInput {
  sessionId: string;
  audio: Uint8Array;
  codec: VoiceAudioCodec;
  operatingProfile?: VoiceOperatingProfile;
  /** Optional JWKS to verify the returned verdict JWS immediately offline. */
  verifyWithJwks?: JwksSource;
  nowSeconds?: number | (() => number);
  signal?: AbortSignal;
}

export interface AnalyzeVoiceResponse {
  verdictJws: string;
  verdict: VoiceLivenessVerdictClaims | null;
  requestId: string | null;
}

export interface WebSocketLike {
  readonly readyState: number;
  send(data: string | Uint8Array | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (event: unknown) => void): void;
  removeEventListener?(type: string, listener: (event: unknown) => void): void;
}

export type WebSocketLikeConstructor = new (
  url: string,
  protocols?: string | string[],
) => WebSocketLike;

export interface VoiceStreamOptions {
  sessionId: string;
  codec: VoiceAudioCodec;
  operatingProfile?: VoiceOperatingProfile;
  /** Optional JWKS to verify incoming verdict JWS frames automatically. */
  verifyWithJwks?: JwksSource;
  nowSeconds?: number | (() => number);
  onVerdict: (frame: {
    verdictJws: string;
    claims: VoiceLivenessVerdictClaims | null;
  }) => void;
  onError?: (error: VoiceClientError) => void;
  onClose?: (info: { code?: number; reason?: string }) => void;
}

export interface VoiceStreamHandle {
  sendAudioChunk(audio: Uint8Array): void;
  flush(): void;
  close(code?: number, reason?: string): void;
  readonly closed: boolean;
}

export class VoiceClientError extends Error {
  constructor(
    public readonly code:
      | "invalid_config"
      | "invalid_audio"
      | "http_error"
      | "invalid_response"
      | "verdict_verification_failed"
      | "stream_error",
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "VoiceClientError";
  }
}

const CODEC_CONTENT_TYPES: Readonly<Record<VoiceAudioCodec, string>> = {
  pcm16_16k: "audio/l16;rate=16000;channels=1",
  opus_16k: "audio/opus;rate=16000",
  opus_48k: "audio/opus;rate=48000",
  mulaw_8k: "audio/basic",
};

const CODEC_DEFAULT_PROFILES: Readonly<
  Record<VoiceAudioCodec, VoiceOperatingProfile>
> = {
  pcm16_16k: "webrtc_16k",
  opus_16k: "webrtc_16k",
  opus_48k: "wideband_clean",
  mulaw_8k: "telephony_8k",
};

function normalizeBaseUrl(baseUrl: string): string {
  if (!isStrictHttpsOrLoopbackUri(baseUrl)) {
    throw new VoiceClientError(
      "invalid_config",
      "Voice client baseUrl must be a strict HTTPS URI (or http://127.0.0.1 for local tests)",
    );
  }
  return baseUrl.replace(/\/+$/, "");
}

function validateAudioInput(audio: unknown, codec: VoiceAudioCodec): Uint8Array {
  if (!(audio instanceof Uint8Array) || audio.byteLength === 0) {
    throw new VoiceClientError(
      "invalid_audio",
      "Audio payload must be a non-empty Uint8Array",
    );
  }
  if (!(codec in CODEC_CONTENT_TYPES)) {
    throw new VoiceClientError("invalid_audio", "Unsupported audio codec");
  }
  return audio;
}

/**
 * Strips any accidental long base64-like tokens or raw byte dumps from error strings
 * so audio payloads can never leak into logs or exceptions.
 */
export function sanitizeVoiceErrorDetail(message: string): string {
  const withoutB64 = message.replace(/[A-Za-z0-9+/_-]{64,}={0,2}/g, "[redacted]");
  return withoutB64.slice(0, 240);
}

function toWebSocketUrl(baseUrl: string, query: URLSearchParams): string {
  const url = new URL(`${baseUrl}/v1/voice/stream`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.search = query.toString();
  return url.toString();
}

function extractWebSocketMessageText(event: unknown): string | null {
  if (typeof event !== "object" || event === null || !("data" in event)) {
    return null;
  }
  const data = (event as { data: unknown }).data;
  if (typeof data === "string") return data;
  if (data instanceof Uint8Array) return decodeUtf8Strict(data);
  if (data instanceof ArrayBuffer) return decodeUtf8Strict(new Uint8Array(data));
  if (ArrayBuffer.isView(data)) {
    return decodeUtf8Strict(
      new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
    );
  }
  return null;
}

function extractWebSocketCloseInfo(event: unknown): {
  code?: number;
  reason?: string;
} {
  if (typeof event !== "object" || event === null) return {};
  const rawCode = "code" in event ? (event as { code: unknown }).code : undefined;
  const rawReason =
    "reason" in event ? (event as { reason: unknown }).reason : undefined;
  return {
    code: typeof rawCode === "number" ? rawCode : undefined,
    reason:
      typeof rawReason === "string"
        ? sanitizeVoiceErrorDetail(rawReason)
        : undefined,
  };
}

export class VoiceLivenessClient {
  readonly #baseUrl: string;
  readonly #apiKey?: string;
  readonly #fetchImpl: typeof globalThis.fetch;
  readonly #wsCtor?: WebSocketLikeConstructor;
  readonly #timeoutMs: number;
  readonly #onDebug?: (event: VoiceClientDebugEvent) => void;

  constructor(config: VoiceClientConfig) {
    this.#baseUrl = normalizeBaseUrl(config.baseUrl);
    this.#apiKey = config.apiKey;
    const fetchImpl = config.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new VoiceClientError(
        "invalid_config",
        "A fetch implementation is required for VoiceLivenessClient",
      );
    }
    this.#fetchImpl = fetchImpl;
    this.#wsCtor =
      config.webSocketCtor ??
      (globalThis.WebSocket as unknown as WebSocketLikeConstructor | undefined);
    this.#timeoutMs = config.timeoutMs ?? 10_000;
    this.#onDebug = config.onDebug;
  }

  /**
   * Sends raw un-denoised audio to `POST /v1/voice/analyze` and returns the
   * signed `VoiceLivenessVerdict` JWS.
   */
  async analyze(input: AnalyzeVoiceInput): Promise<AnalyzeVoiceResponse> {
    if (
      typeof input.sessionId !== "string" ||
      input.sessionId.trim().length === 0
    ) {
      throw new VoiceClientError("invalid_audio", "sessionId is required");
    }
    const audio = validateAudioInput(input.audio, input.codec);
    const operatingProfile =
      input.operatingProfile ?? CODEC_DEFAULT_PROFILES[input.codec];

    this.#onDebug?.({
      type: "analyze_request",
      sessionId: input.sessionId,
      codec: input.codec,
      byteLength: audio.byteLength,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const onAbort = () => controller.abort();
    input.signal?.addEventListener("abort", onAbort, { once: true });

    try {
      const headers: Record<string, string> = {
        "content-type": "application/json",
        accept: "application/json",
        "x-entros-audio-codec": input.codec,
      };
      if (this.#apiKey) {
        headers.authorization = `Bearer ${this.#apiKey}`;
      }

      const response = await this.#fetchImpl(
        `${this.#baseUrl}/v1/voice/analyze`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            session_id: input.sessionId,
            codec: input.codec,
            content_type: CODEC_CONTENT_TYPES[input.codec],
            operating_profile: operatingProfile,
            audio_b64url: base64UrlEncode(audio),
          }),
          signal: controller.signal,
        },
      );

      if (!response.ok) {
        this.#onDebug?.({
          type: "error",
          sessionId: input.sessionId,
          status: response.status,
          message: `Voice analyze HTTP ${response.status}`,
        });
        throw new VoiceClientError(
          "http_error",
          `Voice analyze request failed with HTTP ${response.status}`,
          response.status,
        );
      }

      let body: unknown;
      try {
        body = await response.json();
      } catch {
        throw new VoiceClientError(
          "invalid_response",
          "Voice analyze response is not valid JSON",
          response.status,
        );
      }

      if (!isPlainRecord(body) || typeof body.verdict_jws !== "string") {
        throw new VoiceClientError(
          "invalid_response",
          "Voice analyze response is missing verdict_jws",
          response.status,
        );
      }

      const requestId =
        typeof body.request_id === "string"
          ? body.request_id
          : response.headers?.get("x-request-id") ?? null;

      let verifiedClaims: VoiceLivenessVerdictClaims | null = null;
      if (input.verifyWithJwks) {
        const verified = await verifyVoiceLivenessVerdict({
          jws: body.verdict_jws,
          jwks: input.verifyWithJwks,
          nowSeconds: input.nowSeconds,
        });
        if (!verified.ok) {
          throw new VoiceClientError(
            "verdict_verification_failed",
            `Voice verdict verification failed: ${verified.reason}`,
          );
        }
        verifiedClaims = verified.claims;
      }

      this.#onDebug?.({
        type: "analyze_response",
        sessionId: input.sessionId,
        status: response.status,
        verdict: verifiedClaims?.verdict,
      });

      return {
        verdictJws: body.verdict_jws,
        verdict: verifiedClaims,
        requestId,
      };
    } catch (error) {
      if (error instanceof VoiceClientError) throw error;
      const safeDetail = sanitizeVoiceErrorDetail(
        error instanceof Error ? error.message : "Network error",
      );
      throw new VoiceClientError(
        "http_error",
        `Voice analyze transport failed: ${safeDetail}`,
      );
    } finally {
      clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
    }
  }

  /**
   * Opens a bidirectional WebSocket stream to `GET /v1/voice/stream` and emits
   * rolling signed `VoiceLivenessVerdict` JWS frames as raw audio chunks arrive.
   */
  connectStream(options: VoiceStreamOptions): VoiceStreamHandle {
    if (
      typeof options.sessionId !== "string" ||
      options.sessionId.trim().length === 0
    ) {
      throw new VoiceClientError("invalid_audio", "sessionId is required");
    }
    if (!(options.codec in CODEC_CONTENT_TYPES)) {
      throw new VoiceClientError("invalid_audio", "Unsupported audio codec");
    }
    if (!this.#wsCtor) {
      throw new VoiceClientError(
        "invalid_config",
        "No WebSocket implementation available; pass webSocketCtor in config",
      );
    }

    const operatingProfile =
      options.operatingProfile ?? CODEC_DEFAULT_PROFILES[options.codec];
    const query = new URLSearchParams({
      session_id: options.sessionId,
      codec: options.codec,
      operating_profile: operatingProfile,
    });
    const wsUrl = toWebSocketUrl(this.#baseUrl, query);
    const protocols = this.#apiKey
      ? [`entros.bearer.${this.#apiKey}`]
      : undefined;
    const ws = new this.#wsCtor(wsUrl, protocols);
    const onDebug = this.#onDebug;
    let isClosed = false;

    ws.addEventListener("open", () => {
      onDebug?.({
        type: "stream_open",
        sessionId: options.sessionId,
        codec: options.codec,
      });
    });

    ws.addEventListener("message", (event: unknown) => {
      const raw = extractWebSocketMessageText(event);
      if (raw === null) return;

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        options.onError?.(
          new VoiceClientError(
            "invalid_response",
            "Malformed JSON message from voice stream",
          ),
        );
        return;
      }

      if (!isPlainRecord(parsed) || typeof parsed.verdict_jws !== "string") {
        return;
      }

      const verdictJws = parsed.verdict_jws;
      if (!options.verifyWithJwks) {
        this.#onDebug?.({
          type: "stream_verdict",
          sessionId: options.sessionId,
        });
        options.onVerdict({ verdictJws, claims: null });
        return;
      }

      void verifyVoiceLivenessVerdict({
        jws: verdictJws,
        jwks: options.verifyWithJwks,
        nowSeconds: options.nowSeconds,
      }).then((verified) => {
        if (!verified.ok) {
          options.onError?.(
            new VoiceClientError(
              "verdict_verification_failed",
              `Stream verdict verification failed: ${verified.reason}`,
            ),
          );
          return;
        }
        this.#onDebug?.({
          type: "stream_verdict",
          sessionId: options.sessionId,
          verdict: verified.claims.verdict,
        });
        options.onVerdict({ verdictJws, claims: verified.claims });
      });
    });

    ws.addEventListener("error", () => {
      const err = new VoiceClientError(
        "stream_error",
        "Voice stream transport error",
      );
      this.#onDebug?.({
        type: "error",
        sessionId: options.sessionId,
        message: err.message,
      });
      options.onError?.(err);
    });

    ws.addEventListener("close", (event: unknown) => {
      isClosed = true;
      const { code, reason } = extractWebSocketCloseInfo(event);
      onDebug?.({
        type: "stream_close",
        sessionId: options.sessionId,
      });
      options.onClose?.({ code, reason });
    });

    return {
      sendAudioChunk(audio: Uint8Array): void {
        if (isClosed) {
          throw new VoiceClientError(
            "stream_error",
            "Cannot send audio chunk on a closed voice stream",
          );
        }
        const valid = validateAudioInput(audio, options.codec);
        // Send raw binary audio frames directly; emit byteLength metadata only.
        onDebug?.({
          type: "stream_frame",
          sessionId: options.sessionId,
          codec: options.codec,
          byteLength: valid.byteLength,
        });
        ws.send(valid);
      },
      flush(): void {
        if (!isClosed) {
          ws.send(JSON.stringify({ type: "flush", session_id: options.sessionId }));
        }
      },
      close(code?: number, reason?: string): void {
        if (!isClosed) {
          isClosed = true;
          ws.close(code ?? 1000, reason);
        }
      },
      get closed(): boolean {
        return isClosed;
      },
    };
  }
}

export function createVoiceLivenessClient(
  config: VoiceClientConfig,
): VoiceLivenessClient {
  return new VoiceLivenessClient(config);
}
