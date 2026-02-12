"use client";

import { useMemo, useState } from "react";

import styles from "./page.module.css";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:3001";

function pretty(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export default function Home() {
  const [partyId, setPartyId] = useState("party_123");
  const [payloadText, setPayloadText] = useState(
    '{\n  "amount": 100,\n  "currency": "AED"\n}'
  );
  const [txId, setTxId] = useState("");
  const [result, setResult] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const canSubmit = useMemo(
    () => partyId.trim().length > 0 && payloadText.trim().length > 0,
    [partyId, payloadText]
  );

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: init?.body
        ? {
            "content-type": "application/json",
            ...(init?.headers ?? {}),
          }
        : init?.headers,
    });

    const data = (await response.json()) as T & { error?: string };
    if (!response.ok) {
      throw new Error(data.error ?? "Request failed");
    }
    return data;
  }

  async function encryptAndSave() {
    setBusy(true);
    setError("");
    try {
      const parsedPayload = JSON.parse(payloadText);
      const data = await request<{ id: string }>("/tx/encrypt", {
        method: "POST",
        body: JSON.stringify({ partyId, payload: parsedPayload }),
      });
      setTxId(data.id);
      setResult(pretty(data));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setResult("");
    } finally {
      setBusy(false);
    }
  }

  async function fetchRecord() {
    if (!txId) {
      setError("Enter transaction id first");
      return;
    }

    setBusy(true);
    setError("");
    try {
      const data = await request(`/tx/${txId}`);
      setResult(pretty(data));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setResult("");
    } finally {
      setBusy(false);
    }
  }

  async function decryptRecord() {
    if (!txId) {
      setError("Enter transaction id first");
      return;
    }

    setBusy(true);
    setError("");
    try {
      const data = await request(`/tx/${txId}/decrypt`, {
        method: "POST",
        body: "{}",
      });
      setResult(pretty(data));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setResult("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className={styles.page}>
      <section className={styles.panel}>
        <h1>Secure Transactions</h1>
        <p className={styles.subtitle}>Envelope encryption with AES-256-GCM</p>

        <label className={styles.label}>
          Party ID
          <input
            className={styles.input}
            value={partyId}
            onChange={(e) => setPartyId(e.target.value)}
            placeholder="party_123"
          />
        </label>

        <label className={styles.label}>
          Payload JSON
          <textarea
            className={styles.textarea}
            value={payloadText}
            onChange={(e) => setPayloadText(e.target.value)}
            rows={8}
          />
        </label>

        <label className={styles.label}>
          Transaction ID
          <input
            className={styles.input}
            value={txId}
            onChange={(e) => setTxId(e.target.value)}
            placeholder="auto-filled after encrypt"
          />
        </label>

        <div className={styles.actions}>
          <button
            className={styles.button}
            onClick={encryptAndSave}
            disabled={busy || !canSubmit}
          >
            Encrypt and Save
          </button>
          <button className={styles.button} onClick={fetchRecord} disabled={busy}>
            Fetch
          </button>
          <button
            className={styles.button}
            onClick={decryptRecord}
            disabled={busy}
          >
            Decrypt
          </button>
        </div>

        {error ? <p className={styles.error}>{error}</p> : null}
      </section>

      <section className={styles.panel}>
        <h2>Result</h2>
        <pre className={styles.result}>{result || "No result yet."}</pre>
      </section>
    </main>
  );
}
