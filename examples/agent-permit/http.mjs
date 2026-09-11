import { createServer } from "node:http";

const MAX_REQUEST_BYTES = 16 * 1024;
const ROUTES = new Set(["/permit-requests", "/settlements"]);

export function createAgentPermitServer(service) {
  return createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("cache-control", "no-store");
    const origin = request.headers.origin;
    if (origin && origin !== `http://${request.headers.host}`) {
      response.writeHead(403).end(JSON.stringify({ error: "origin_invalid" }));
      return;
    }
    if (request.method === "GET" && request.url === "/actions") {
      response.writeHead(200).end(JSON.stringify(service.actions()));
      return;
    }
    if (request.method !== "POST" || !ROUTES.has(request.url)) {
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
          response.writeHead(413).end(JSON.stringify({ error: "request_too_large" }));
          return;
        }
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const result =
        request.url === "/permit-requests"
          ? await service.issue({ agent: body?.agent, action: body?.action })
          : await service.settle(body);
      response.writeHead(200).end(JSON.stringify(result));
    } catch {
      response.writeHead(400).end(JSON.stringify({ error: "invalid_request" }));
    }
  });
}
