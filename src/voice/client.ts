/**
 * Voice Liveness REST (`POST /v1/voice/analyze`) and WebSocket streaming
 * (`GET /v1/voice/stream`) clients supporting PCM16 (8/16 kHz), Opus (16/48 kHz),
 * G.711 mu-law/A-law (8 kHz), and WAV (REST only).
 *
 * Raw audio bytes and Base64 audio payloads are never emitted in errors or
 * debug callbacks.
 */

import {
  base64Encode,
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
  | "pcm16_8k"
  | "opus_16k"
  | "opus_48k"
  | "mulaw_8k"
  | "alaw_8k"
  | "wav";

export type VoiceStreamCodec = Exclude<VoiceAudioCodec, "wav">;

export type VoiceWireEncoding = "pcm16" | "opus" | "mulaw" | "alaw" | "wav";

interface CodecWireMapping {
  readonly encoding: VoiceWireEncoding;
  readonly sampleRateHz: number | null;
  readonly defaultProfile: VoiceOperatingProfile;
  readonly streamable: boolean;
}

const CODEC_WIRE_MAP: Readonly<Record<VoiceAudioCodec, CodecWireMapping>> = {
  pcm16_16k: {
    encoding: "pcm16",
    sampleRateHz: 16_000,
    defaultProfile: "webrtc_16k",
    streamable: true,
  },
  pcm16_8k: {
    encoding: "pcm16",
    sampleRateHz: 8_000,
    defaultProfile: "telephony_8k",
    streamable: true,
  },
  opus_16k: {
    encoding: "opus",
    sampleRateHz: 16_000,
    defaultProfile: "webrtc_16k",
    streamable: true,
  },
  opus_48k: {
    encoding: "opus",
    sampleRateHz: 48_000,
    defaultProfile: "wideband_clean",
    streamable: true,
  },
  mulaw_8k: {
    encoding: "mulaw",
    sampleRateHz: 8_000,
    defaultProfile: "telephony_8k",
    streamable: true,
  },
  alaw_8k: {
    encoding: "alaw",
    sampleRateHz: 8_000,
    defaultProfile: "telephony_8k",
    streamable: true,
  },
  wav: {
    encoding: "wav",
    sampleRateHz: null,
    defaultProfile: "webrtc_16k",
    streamable: false,
  },
};

const WS_OPEN = 1;
const DEFAULT_STREAM_OPEN_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_INBOUND_MESSAGE_BYTES = 262_144;

export interface WebSocketConnectInit {
  headers: Record<string, string>;
  /** Optional short-lived stream token for runtimes using custom headerless auth bridges. */
  streamToken?: string;
}

export type WebSocketFactory = (
  url: string,
  init: WebSocketConnectInit,
) => WebSocketLike;

export interface VoiceClientConfig {
  /** Base HTTPS URI (or http://127.0.0.1 for local loopback tests). */
  baseUrl: string;
  /** Optional Bearer API key for hosted or VPC firewall API authentication. */
  apiKey?: string;
  /** Optional custom fetch implementation. */
  fetch?: typeof globalThis.fetch;
  /** Optional WebSocket constructor override for non-global runtimes or tests. */
  webSocketCtor?: WebSocketLikeConstructor;
  /** Optional custom WebSocket factory receiving HTTP upgrade headers (recommended in Node/server runtimes). */
  webSocketFactory?: WebSocketFactory;
  /** Optional extra HTTP upgrade headers for WebSocket stream connections. */
  webSocketHeaders?: Record<string, string>;
  /** Default REST request timeout in milliseconds. Default 10,000. */
  timeoutMs?: number;
  /** Timeout in milliseconds waiting for WebSocket open before aborting. Default 10,000. */
  streamOpenTimeoutMs?: number;
  /** Maximum accepted inbound WebSocket text/binary message size in bytes. Default 262,144. */
  maxInboundMessageBytes?: number;
  /** Optional metadata-only debug hook (never receives audio bytes or base64). */
  onDebug?: (event: VoiceClientDebugEvent) => void;
}

export interface VoiceClientDebugEvent {
  type:
    | "analyze_request"
    | "analyze_response"
    | "stream_open"
    | "stream_frame"
    | "stream_verdict"
    | "stream_close"
    | "error";
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
  /** Optional local revoked kid list applied during offline verdict verification. */
  revokedKids?: ReadonlySet<string> | readonly string[];
  nowSeconds?: number | (() => number);
  signal?: AbortSignal;
}

export interface AnalyzeVoiceResponse {
  verdictJws: string;
  verdict: VoiceLivenessVerdictClaims | null;
  requestId: string | null;
  inferenceMs: number | null;
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
  options?: string | string[] | { headers?: Record<string, string> },
) => WebSocketLike;

export interface VoiceStreamOptions {
  sessionId: string;
  codec: VoiceStreamCodec;
  operatingProfile?: VoiceOperatingProfile;
  /** Optional stream adapter query selector (`webrtc`, `twilio`, `genesys`). Default `webrtc`. */
  adapter?: "webrtc" | "twilio" | "genesys";
  /**
   * Optional short-lived stream token for runtimes where a separate token minting
   * endpoint issues ephemeral stream credentials. Permanent API keys are never
   * placed in WebSocket subprotocols or URL query strings.
   */
  streamToken?: string;
  /** Optional per-stream upgrade headers merged with client headers. */
  headers?: Record<string, string>;
  /** Optional JWKS to verify incoming verdict JWS frames automatically. */
  verifyWithJwks?: JwksSource;
  /** Optional local revoked kid list applied during offline verdict verification. */
  revokedKids?: ReadonlySet<string> | readonly string[];
  nowSeconds?: number | (() => number);
  /** Timeout in milliseconds waiting for WebSocket open. Overrides client default. */
  openTimeoutMs?: number;
  /** Maximum inbound WebSocket message size in bytes. Overrides client default. */
  maxInboundMessageBytes?: number;
  onVerdict: (frame: {
    verdictJws: string;
    claims: VoiceLivenessVerdictClaims | null;
    seq?: number;
    inferenceMs?: number | null;
  }) => void;
  onError?: (error: VoiceClientError) => void;
  onClose?: (info: { code?: number; reason?: string }) => void;
}

export interface VoiceStreamHandle {
  sendAudioChunk(audio: Uint8Array): void;
  flush(): void;
  pause(): void;
  resume(): void;
  stop(): void;
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
    public readonly serverCode?: string,
  ) {
    super(message);
    this.name = "VoiceClientError";
  }
}

export function mapVoiceCodecToWire(codec: VoiceAudioCodec): {
  encoding: VoiceWireEncoding;
  sample_rate_hz: number | null;
  operating_profile: VoiceOperatingProfile;
} {
  const entry = CODEC_WIRE_MAP[codec];
  if (!entry) {
    throw new VoiceClientError("invalid_audio", "Unsupported audio codec");
  }
  return {
    encoding: entry.encoding,
    sample_rate_hz: entry.sampleRateHz,
    operating_profile: entry.defaultProfile,
  };
}

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
  if (!(codec in CODEC_WIRE_MAP)) {
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

function toWebSocketUrl(baseUrl: string, adapter: string): string {
  const url = new URL(`${baseUrl}/v1/voice/stream`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("adapter", adapter);
  return url.toString();
}

function extractWebSocketMessageText(
  event: unknown,
  maxBytes: number,
): { ok: true; text: string | null } | { ok: false; reason: "too_large" } {
  if (typeof event !== "object" || event === null || !("data" in event)) {
    return { ok: true, text: null };
  }
  const data = (event as { data: unknown }).data;
  if (typeof data === "string") {
    if (data.length > maxBytes) return { ok: false, reason: "too_large" };
    return { ok: true, text: data };
  }
  if (data instanceof Uint8Array) {
    if (data.byteLength > maxBytes) return { ok: false, reason: "too_large" };
    return { ok: true, text: decodeUtf8Strict(data) };
  }
  if (data instanceof ArrayBuffer) {
    if (data.byteLength > maxBytes) return { ok: false, reason: "too_large" };
    return { ok: true, text: decodeUtf8Strict(new Uint8Array(data)) };
  }
  if (ArrayBuffer.isView(data)) {
    if (data.byteLength > maxBytes) return { ok: false, reason: "too_large" };
    return {
      ok: true,
      text: decodeUtf8Strict(
        new Uint8Array(data.buffer, data.byteOffset, data.byteLength),
      ),
    };
  }
  return { ok: true, text: null };
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
  readonly #wsFactory?: WebSocketFactory;
  readonly #wsHeaders: Readonly<Record<string, string>>;
  readonly #timeoutMs: number;
  readonly #streamOpenTimeoutMs: number;
  readonly #maxInboundMessageBytes: number;
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
    this.#wsFactory = config.webSocketFactory;
    this.#wsCtor =
      config.webSocketCtor ??
      (globalThis.WebSocket as unknown as WebSocketLikeConstructor | undefined);
    this.#wsHeaders = { ...(config.webSocketHeaders ?? {}) };
    this.#timeoutMs = config.timeoutMs ?? 10_000;
    this.#streamOpenTimeoutMs =
      config.streamOpenTimeoutMs ?? DEFAULT_STREAM_OPEN_TIMEOUT_MS;
    this.#maxInboundMessageBytes =
      config.maxInboundMessageBytes ?? DEFAULT_MAX_INBOUND_MESSAGE_BYTES;
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
    const wire = CODEC_WIRE_MAP[input.codec];
    const operatingProfile = input.operatingProfile ?? wire.defaultProfile;

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
      };
      if (this.#apiKey) {
        headers.authorization = `Bearer ${this.#apiKey}`;
      }

      const payload: Record<string, unknown> = {
        session_id: input.sessionId,
        audio_b64: base64Encode(audio),
        encoding: wire.encoding,
        operating_profile: operatingProfile,
      };
      if (wire.sampleRateHz !== null) {
        payload.sample_rate_hz = wire.sampleRateHz;
      }

      const response = await this.#fetchImpl(
        `${this.#baseUrl}/v1/voice/analyze`,
        {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
          signal: controller.signal,
        },
      );

      if (!response.ok) {
        let serverCode: string | undefined;
        try {
          const errJson: unknown = await response.json();
          if (isPlainRecord(errJson) && typeof errJson.error === "string") {
            serverCode = errJson.error;
          }
        } catch {
          // Ignore non-JSON error body.
        }
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
          serverCode,
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
      const inferenceMs =
        typeof body.inference_ms === "number" && Number.isFinite(body.inference_ms)
          ? body.inference_ms
          : null;

      let verifiedClaims: VoiceLivenessVerdictClaims | null = null;
      if (input.verifyWithJwks) {
        const verified = await verifyVoiceLivenessVerdict({
          jws: body.verdict_jws,
          jwks: input.verifyWithJwks,
          revokedKids: input.revokedKids,
          nowSeconds: input.nowSeconds,
        });
        if (!verified.ok) {
          throw new VoiceClientError(
            "verdict_verification_failed",
            `Voice verdict verification failed: ${verified.reason}`,
          );
        }
        if (verified.claims.session_id !== input.sessionId) {
          throw new VoiceClientError(
            "verdict_verification_failed",
            "Voice verdict session_id does not match request session_id",
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
        inferenceMs,
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
   *
   * Authenticates via `Authorization: Bearer <token>` upgrade header (never
   * `Sec-WebSocket-Protocol` or URL query strings). In browser runtimes that
   * cannot set custom upgrade headers, provide `webSocketFactory` backed by a
   * BFF proxy or short-lived `streamToken`.
   */
  connectStream(options: VoiceStreamOptions): VoiceStreamHandle {
    if (
      typeof options.sessionId !== "string" ||
      options.sessionId.trim().length === 0
    ) {
      throw new VoiceClientError("invalid_audio", "sessionId is required");
    }
    const wire = CODEC_WIRE_MAP[options.codec];
    if (!wire || !wire.streamable || wire.sampleRateHz === null) {
      throw new VoiceClientError(
        "invalid_audio",
        "Unsupported streaming audio codec",
      );
    }
    if (!this.#wsFactory && !this.#wsCtor) {
      throw new VoiceClientError(
        "invalid_config",
        "No WebSocket implementation available; pass webSocketFactory or webSocketCtor in config",
      );
    }

    const operatingProfile = options.operatingProfile ?? wire.defaultProfile;
    const wsUrl = toWebSocketUrl(this.#baseUrl, options.adapter ?? "webrtc");
    const upgradeHeaders: Record<string, string> = {
      ...this.#wsHeaders,
      ...(options.headers ?? {}),
    };
    const bearer = options.streamToken ?? this.#apiKey;
    if (bearer && !("authorization" in upgradeHeaders) && !("Authorization" in upgradeHeaders)) {
      upgradeHeaders.Authorization = `Bearer ${bearer}`;
    }

    let ws: WebSocketLike;
    if (this.#wsFactory) {
      ws = this.#wsFactory(wsUrl, {
        headers: upgradeHeaders,
        ...(options.streamToken ? { streamToken: options.streamToken } : {}),
      });
    } else {
      const Ctor = this.#wsCtor!;
      if (Object.keys(upgradeHeaders).length > 0) {
        try {
          ws = new Ctor(wsUrl, { headers: upgradeHeaders });
        } catch (error) {
          if (error instanceof SyntaxError) {
            throw new VoiceClientError(
              "invalid_config",
              "WebSocket constructor rejected custom upgrade headers (strict WHATWG WebSocket); pass webSocketFactory backed by a BFF proxy or header-capable WebSocket client",
            );
          }
          throw error;
        }
      } else {
        ws = new Ctor(wsUrl);
      }
    }

    const onDebug = this.#onDebug;
    const maxInboundBytes =
      options.maxInboundMessageBytes ?? this.#maxInboundMessageBytes;
    const openTimeoutMs = options.openTimeoutMs ?? this.#streamOpenTimeoutMs;
    let isClosed = false;
    let closeNotified = false;
    let startSent = false;
    let openTimer: ReturnType<typeof setTimeout> | null = null;
    let verifyChain: Promise<void> = Promise.resolve();

    const clearOpenTimer = () => {
      if (openTimer !== null) {
        clearTimeout(openTimer);
        openTimer = null;
      }
    };

    const sendStartFrame = () => {
      if (startSent || isClosed || ws.readyState !== WS_OPEN) return;
      startSent = true;
      try {
        ws.send(
          JSON.stringify({
            type: "start",
            session_id: options.sessionId,
            codec: wire.encoding,
            sample_rate_hz: wire.sampleRateHz,
            operating_profile: operatingProfile,
          }),
        );
      } catch (error) {
        if (isClosed) return;
        const safe = sanitizeVoiceErrorDetail(
          error instanceof Error
            ? error.message
            : "Failed to send voice stream start frame",
        );
        options.onError?.(new VoiceClientError("stream_error", safe));
      }
    };

    if (ws.readyState !== WS_OPEN && openTimeoutMs > 0) {
      openTimer = setTimeout(() => {
        openTimer = null;
        if (!isClosed && ws.readyState !== WS_OPEN) {
          isClosed = true;
          try {
            ws.close(1000, "open_timeout");
          } catch {
            // Ignore close failures on timed-out socket.
          }
          options.onError?.(
            new VoiceClientError(
              "stream_error",
              "Voice stream connection open timed out",
            ),
          );
        }
      }, openTimeoutMs);
    }

    ws.addEventListener("open", () => {
      clearOpenTimer();
      if (isClosed) return;
      sendStartFrame();
      onDebug?.({
        type: "stream_open",
        sessionId: options.sessionId,
        codec: options.codec,
      });
    });

    // Support test fakes that instantiate already in OPEN state without emitting "open".
    if (ws.readyState === WS_OPEN) {
      sendStartFrame();
    }

    ws.addEventListener("message", (event: unknown) => {
      if (isClosed) return;
      const extracted = extractWebSocketMessageText(event, maxInboundBytes);
      if (!extracted.ok) {
        options.onError?.(
          new VoiceClientError(
            "invalid_response",
            "Inbound voice stream frame exceeds maximum allowed size",
          ),
        );
        return;
      }
      const raw = extracted.text;
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

      if (!isPlainRecord(parsed)) {
        return;
      }

      if (parsed.type === "error") {
        const serverCode =
          typeof parsed.code === "string"
            ? parsed.code
            : typeof parsed.error_code === "string"
              ? parsed.error_code
              : "stream_error";
        const detail =
          typeof parsed.message === "string"
            ? sanitizeVoiceErrorDetail(parsed.message)
            : `Voice stream server error: ${serverCode}`;
        const err = new VoiceClientError(
          "stream_error",
          detail,
          undefined,
          serverCode,
        );
        this.#onDebug?.({
          type: "error",
          sessionId: options.sessionId,
          message: detail,
        });
        options.onError?.(err);
        return;
      }

      const isVerdictFrame =
        parsed.type === "verdict" || parsed.type === undefined;
      if (!isVerdictFrame || typeof parsed.verdict_jws !== "string") {
        return;
      }

      const verdictJws = parsed.verdict_jws;
      const seq = typeof parsed.seq === "number" ? parsed.seq : undefined;
      const inferenceMs =
        typeof parsed.inference_ms === "number" &&
        Number.isFinite(parsed.inference_ms)
          ? parsed.inference_ms
          : null;

      if (!options.verifyWithJwks) {
        this.#onDebug?.({
          type: "stream_verdict",
          sessionId: options.sessionId,
        });
        options.onVerdict({ verdictJws, claims: null, seq, inferenceMs });
        return;
      }

      const verifyJwks = options.verifyWithJwks;
      verifyChain = verifyChain
        .then(async () => {
          if (isClosed) return;
          const verified = await verifyVoiceLivenessVerdict({
            jws: verdictJws,
            jwks: verifyJwks,
            revokedKids: options.revokedKids,
            nowSeconds: options.nowSeconds,
          });
          if (isClosed) return;
          if (!verified.ok) {
            options.onError?.(
              new VoiceClientError(
                "verdict_verification_failed",
                `Stream verdict verification failed: ${verified.reason}`,
              ),
            );
            return;
          }
          if (verified.claims.session_id !== options.sessionId) {
            options.onError?.(
              new VoiceClientError(
                "verdict_verification_failed",
                "Stream verdict session_id does not match active session",
              ),
            );
            return;
          }
          this.#onDebug?.({
            type: "stream_verdict",
            sessionId: options.sessionId,
            verdict: verified.claims.verdict,
          });
          options.onVerdict({
            verdictJws,
            claims: verified.claims,
            seq,
            inferenceMs,
          });
        })
        .catch((error: unknown) => {
          if (isClosed) return;
          const safe = sanitizeVoiceErrorDetail(
            error instanceof Error
              ? error.message
              : "Unexpected stream verdict verification error",
          );
          options.onError?.(
            new VoiceClientError("verdict_verification_failed", safe),
          );
        });
    });

    ws.addEventListener("error", () => {
      clearOpenTimer();
      if (isClosed) return;
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
      clearOpenTimer();
      isClosed = true;
      if (closeNotified) return;
      closeNotified = true;
      const { code, reason } = extractWebSocketCloseInfo(event);
      onDebug?.({
        type: "stream_close",
        sessionId: options.sessionId,
      });
      options.onClose?.({ code, reason });
    });

    const assertOpen = (actionName: string) => {
      if (isClosed || ws.readyState !== WS_OPEN) {
        throw new VoiceClientError(
          "stream_error",
          `Cannot ${actionName} when voice stream is not open`,
        );
      }
    };

    const sendControl = (type: "flush" | "pause" | "resume" | "stop") => {
      assertOpen(`send ${type}`);
      ws.send(JSON.stringify({ type }));
    };

    return {
      sendAudioChunk(audio: Uint8Array): void {
        assertOpen("send audio chunk");
        const valid = validateAudioInput(audio, options.codec);
        onDebug?.({
          type: "stream_frame",
          sessionId: options.sessionId,
          codec: options.codec,
          byteLength: valid.byteLength,
        });
        ws.send(valid);
      },
      flush(): void {
        sendControl("flush");
      },
      pause(): void {
        sendControl("pause");
      },
      resume(): void {
        sendControl("resume");
      },
      stop(): void {
        sendControl("stop");
      },
      close(code?: number, reason?: string): void {
        clearOpenTimer();
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
