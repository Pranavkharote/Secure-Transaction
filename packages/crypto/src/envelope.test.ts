import test from "node:test";
import assert from "node:assert/strict";

import {
  decryptTransaction,
  encryptTransaction,
  parseMasterKeyHex,
} from "./index.js";

const MASTER_KEY_HEX =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test("encrypt -> decrypt returns original payload", () => {
  const payload = { amount: 100, currency: "AED", nested: { ok: true } };
  const record = encryptTransaction({
    partyId: "party_123",
    payload,
    masterKeyHex: MASTER_KEY_HEX,
  });

  const decrypted = decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX });
  assert.deepEqual(decrypted, payload);
});

test("tampered payload ciphertext fails", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 1 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  record.payload_ct = `ff${record.payload_ct.slice(2)}`;
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX }),
    /decryption failed/
  );
});

test("tampered payload tag fails", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 1 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  record.payload_tag = `aa${record.payload_tag.slice(2)}`;
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX }),
    /decryption failed/
  );
});

test("tampered metadata fails", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 42 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  record.partyId = "party_999";
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX }),
    /decryption failed/
  );
});

test("wrong nonce length fails validation", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 1 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  record.payload_nonce = "00";
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX }),
    /payload_nonce: invalid length/
  );
});

test("invalid hex fails validation", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 1 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  record.payload_ct = "zz";
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX }),
    /payload_ct: invalid hex/
  );
});

test("wrong tag length fails validation", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 1 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  record.payload_tag = "00";
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: MASTER_KEY_HEX }),
    /payload_tag: invalid length/
  );
});

test("wrong master key fails decryption", () => {
  const record = encryptTransaction({
    partyId: "party_123",
    payload: { amount: 1 },
    masterKeyHex: MASTER_KEY_HEX,
  });

  const wrongKey =
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  assert.throws(
    () => decryptTransaction({ record, masterKeyHex: wrongKey }),
    /decryption failed/
  );
});

test("invalid master key hex is rejected", () => {
  assert.throws(() => parseMasterKeyHex("zz"), /master key: invalid hex/);
});

test("non-serializable payload is rejected", () => {
  assert.throws(
    () =>
      encryptTransaction({
        partyId: "party_123",
        payload: undefined,
        masterKeyHex: MASTER_KEY_HEX,
      }),
    /payload is not JSON-serializable/
  );
});
