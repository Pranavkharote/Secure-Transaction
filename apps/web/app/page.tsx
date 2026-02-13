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
  <header className={styles.header}>
    <h1>Secure Transaction Console</h1>
    <p className={styles.subtitle}>
      Envelope Encryption using AES-256-GCM with Integrity Protection
    </p>
  </header>

  <section className={styles.panel}>
    <h2>Transaction Input</h2>

    <div className={styles.field}>
      <label>Party ID</label>
      <input
        className={styles.input}
        value={partyId}
        onChange={(e) => setPartyId(e.target.value)}
        placeholder="e.g. party_123"
      />
    </div>

    <div className={styles.field}>
      <label>Payload (JSON Format)</label>
      <textarea
        className={styles.textarea}
        value={payloadText}
        onChange={(e) => setPayloadText(e.target.value)}
        rows={8}
        placeholder='{"amount": 5000, "currency": "INR"}'
      />
    </div>

    <div className={styles.field}>
      <label>Transaction ID</label>
      <input
        className={styles.input}
        value={txId}
        onChange={(e) => setTxId(e.target.value)}
        placeholder="Auto-generated after encryption"
      />
    </div>

    <div className={styles.actions}>
      <button
        className={styles.primaryButton}
        onClick={encryptAndSave}
        disabled={busy || !canSubmit}
      >
        Encrypt & Store
      </button>

      <button
        className={styles.secondaryButton}
        onClick={fetchRecord}
        disabled={busy}
      >
        Retrieve Record
      </button>

      <button
        className={styles.dangerButton}
        onClick={decryptRecord}
        disabled={busy}
      >
        Decrypt Securely
      </button>
    </div>

    {error && <div className={styles.errorBox}>{error}</div>}
  </section>

  <section className={styles.panel}>
    <h2>Encrypted / Decrypted Output</h2>
    <pre className={styles.result}>
      {result || "Awaiting transaction execution..."}
    </pre>
  </section>
</main>

  );
}
