import { createServer } from "node:http";

const MAX_REQUEST_BYTES = 16 * 1024;
const POST_ROUTES = new Set([
  "/warm-check",
  "/action-challenges",
  "/action-settlements",
  "/agent-permit-requests",
  "/agent-permit-settlements",
  "/realms-preflight",
]);

/**
 * Bounded JSON loopback server exposing the reference consumer endpoints.
 * Enforces an explicit origin allowlist, content-type, and request byte cap.
 */
export function createReferenceConsumerServer(
  service,
  { allowedOrigins } = {},
) {
  const allowlist = allowedOrigins ? new Set(allowedOrigins) : null;

  return createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("cache-control", "no-store");

    const origin = request.headers.origin;
    const expectedOrigin = `http://${request.headers.host}`;
    const effectiveOrigin = origin ?? expectedOrigin;
    const originAllowed = allowlist
      ? allowlist.has(effectiveOrigin)
      : origin === undefined || origin === expectedOrigin;
    if (!originAllowed) {
      response.writeHead(403).end(JSON.stringify({ error: "origin_invalid" }));
      return;
    }

    if (request.method === "GET" && request.url === "/actions") {
      response.writeHead(200).end(JSON.stringify(service.actions()));
      return;
    }
    if (request.method === "GET" && request.url === "/telemetry") {
      response.writeHead(200).end(JSON.stringify(service.telemetrySummary()));
      return;
    }

    if (request.method !== "POST" || !POST_ROUTES.has(request.url)) {
      response.writeHead(404).end(JSON.stringify({ error: "not_found" }));
      return;
    }
    if (request.headers["content-type"]?.split(";")[0] !== "application/json") {
      response.writeHead(415).end(JSON.stringify({ error: "json_required" }));
      return;
    }

    try {
      const chunks = [];
      let length = 0;
      for await (const chunk of request) {
        length += chunk.length;
        if (length > MAX_REQUEST_BYTES) {
          response
            .writeHead(413)
            .end(JSON.stringify({ error: "request_too_large" }));
          return;
        }
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      let result;
      switch (request.url) {
        case "/warm-check":
          result = await service.checkWarmPolicy({
            walletPubkey: body?.walletPubkey,
            candidateSignatures: body?.candidateSignatures ?? [],
            requireLegacyAttestation: body?.requireLegacyAttestation === true,
            origin: effectiveOrigin,
          });
          break;
        case "/action-challenges":
          result = service.issueActionChallenge({
            wallet: body?.wallet,
            action: body?.action,
            origin: effectiveOrigin,
          });
          break;
        case "/action-settlements":
          result = await service.settleAction({
            challenge: body?.challenge,
            signature: body?.signature,
            verifiedTransaction: body?.verifiedTransaction,
            origin: effectiveOrigin,
          });
          break;
        case "/agent-permit-requests":
          result = await service.requestAgentPermit({
            agent: body?.agent,
            action: body?.action,
            origin: effectiveOrigin,
          });
          break;
        case "/agent-permit-settlements":
          result = await service.settleAgentPermit(body, {
            origin: effectiveOrigin,
          });
          break;
        case "/realms-preflight":
          result = await service.preflightRealms({
            realm: body?.realm,
            governingTokenMint: body?.governingTokenMint,
            voter: body?.voter,
            action: body?.action,
            actionTarget: body?.actionTarget,
            origin: effectiveOrigin,
          });
          break;
      }
      response.writeHead(200).end(JSON.stringify(result));
    } catch {
      response.writeHead(400).end(JSON.stringify({ error: "invalid_request" }));
    }
  });
}
