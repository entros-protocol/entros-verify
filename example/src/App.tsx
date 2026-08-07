import { useCallback, useState } from "react";

import {
  EntrosVerify,
  type EntrosVerifyError,
  type EntrosVerifyProgress,
  type EntrosVerifyResult,
} from "@entros/verify";
import { Connection, PublicKey } from "@solana/web3.js";

const POPUP_BASE_ORIGIN = "http://localhost:3000";
const DEVNET_RPC = "https://api.devnet.solana.com";
const ATTESTATION_POLL_MAX_MS = 60_000;
const ATTESTATION_POLL_INTERVAL_MS = 5_000;

type LogKind = "verified" | "error" | "progress";
type LogEntry = { ts: number; kind: LogKind; data: unknown };

type AttestationStatus =
  | { state: "idle" }
  | { state: "polling"; pda: string }
  | { state: "found"; pda: string; bytes: number }
  | { state: "not_found"; pda: string };

const containerStyle: React.CSSProperties = {
  fontFamily: "ui-monospace, SF Mono, Menlo, monospace",
  maxWidth: 880,
  margin: "0 auto",
  padding: "32px 24px",
  color: "#1a1a1a",
};

const sectionStyle: React.CSSProperties = {
  marginTop: 32,
  padding: 16,
  border: "1px solid #d8d8d8",
  borderRadius: 8,
};

const buttonStyle: React.CSSProperties = {
  background: "#0a0a0f",
  color: "#fff",
  border: "1px solid #0a0a0f",
  borderRadius: 999,
  padding: "10px 20px",
  fontFamily: "inherit",
  fontSize: 14,
  cursor: "pointer",
};

const logBoxStyle: React.CSSProperties = {
  background: "#f6f6f6",
  border: "1px solid #e0e0e0",
  borderRadius: 6,
  padding: 12,
  maxHeight: 360,
  overflow: "auto",
  fontSize: 12,
  whiteSpace: "pre-wrap",
};

export function App() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<EntrosVerifyResult | null>(null);
  const [attestation, setAttestation] = useState<AttestationStatus>({
    state: "idle",
  });

  const append = useCallback((kind: LogKind, data: unknown) => {
    setLogs((prev) => [...prev, { ts: Date.now(), kind, data }]);
  }, []);

  const pollAttestation = useCallback(async (pda: string) => {
    setAttestation({ state: "polling", pda });
    const conn = new Connection(DEVNET_RPC, "confirmed");
    const pubkey = new PublicKey(pda);
    const start = Date.now();
    while (Date.now() - start < ATTESTATION_POLL_MAX_MS) {
      const account = await conn.getAccountInfo(pubkey).catch(() => null);
      if (account) {
        setAttestation({
          state: "found",
          pda,
          bytes: account.data.length,
        });
        return;
      }
      await new Promise((r) => setTimeout(r, ATTESTATION_POLL_INTERVAL_MS));
    }
    setAttestation({ state: "not_found", pda });
  }, []);

  const handleVerified = useCallback(
    (r: EntrosVerifyResult) => {
      setResult(r);
      append("verified", r);
      void pollAttestation(r.attestationPda);
    },
    [append, pollAttestation],
  );

  const handleError = useCallback(
    (e: EntrosVerifyError) => {
      append("error", e);
    },
    [append],
  );

  const handleProgress = useCallback(
    (p: EntrosVerifyProgress) => {
      append("progress", p);
    },
    [append],
  );

  return (
    <div style={containerStyle}>
      <header>
        <h1 style={{ margin: 0, fontSize: 28 }}>Entros Verify — Example Integrator</h1>
        <p style={{ marginTop: 8, color: "#666" }}>
          End-to-end against a localhost popup host at {POPUP_BASE_ORIGIN}.
          Trigger the verification, watch postMessage events stream into the
          log, and confirm the on-chain attestation appears.
        </p>
      </header>

      <section style={sectionStyle}>
        <h2 style={{ marginTop: 0, fontSize: 16 }}>Trigger</h2>
        <EntrosVerify
          baseOrigin={POPUP_BASE_ORIGIN}
          integratorKey="demo-integrator"
          cluster="devnet"
          onVerified={handleVerified}
          onError={handleError}
          onProgress={handleProgress}
          style={buttonStyle}
        >
          Verify with Entros
        </EntrosVerify>
      </section>

      {result && (
        <section style={sectionStyle}>
          <h2 style={{ marginTop: 0, fontSize: 16 }}>Verified payload</h2>
          <dl style={{ display: "grid", gridTemplateColumns: "180px 1fr", rowGap: 6, columnGap: 12, margin: 0 }}>
            <dt style={{ color: "#666" }}>wallet_pubkey</dt>
            <dd style={{ margin: 0, wordBreak: "break-all" }}>{result.walletPubkey}</dd>
            <dt style={{ color: "#666" }}>attestation_pda</dt>
            <dd style={{ margin: 0, wordBreak: "break-all" }}>
              {result.attestationPda}{" "}
              <span style={{ color: "#666" }}>
                ({renderAttestationStatus(attestation)})
              </span>
            </dd>
            <dt style={{ color: "#666" }}>tx_sig</dt>
            <dd style={{ margin: 0, wordBreak: "break-all" }}>
              <a
                href={`https://explorer.solana.com/tx/${result.txSig}?cluster=devnet`}
                target="_blank"
                rel="noopener noreferrer"
              >
                {result.txSig}
              </a>
            </dd>
            <dt style={{ color: "#666" }}>trust_score</dt>
            <dd style={{ margin: 0 }}>{result.trustScore}</dd>
            <dt style={{ color: "#666" }}>cluster</dt>
            <dd style={{ margin: 0 }}>{result.cluster}</dd>
          </dl>
        </section>
      )}

      <section style={sectionStyle}>
        <header style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between" }}>
          <h2 style={{ margin: 0, fontSize: 16 }}>Event log ({logs.length})</h2>
          <button
            onClick={() => setLogs([])}
            style={{
              ...buttonStyle,
              background: "transparent",
              color: "#666",
              border: "1px solid #ccc",
              padding: "4px 12px",
              fontSize: 12,
            }}
          >
            Clear
          </button>
        </header>
        <pre style={logBoxStyle}>
          {logs.length === 0
            ? "No events yet. Click Verify to start."
            : logs.map(formatLog).join("\n")}
        </pre>
      </section>
    </div>
  );
}

function renderAttestationStatus(s: AttestationStatus): string {
  switch (s.state) {
    case "idle":
      return "—";
    case "polling":
      return "polling on-chain…";
    case "found":
      return `on-chain (${s.bytes} bytes)`;
    case "not_found":
      return "not yet on-chain after 60s";
  }
}

function formatLog(entry: LogEntry): string {
  const ts = new Date(entry.ts).toISOString().slice(11, 23);
  return `[${ts}] ${entry.kind.toUpperCase().padEnd(8)} ${JSON.stringify(entry.data)}`;
}
