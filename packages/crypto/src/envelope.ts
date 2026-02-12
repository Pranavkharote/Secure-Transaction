import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  randomUUID,
} from "node:crypto";

import type { TxSecureRecord } from "./types.js";

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

function isValidHex(str: string): boolean {
  return str.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(str);
}

function assertHexLength(hex: string, expectedBytes: number, field: string) {
  if (!isValidHex(hex)) {
    throw new Error(`${field}: invalid hex`);
  }

  if (hex.length !== expectedBytes * 2) {
    throw new Error(`${field}: invalid length`);
  }
}

function fromHex(hex: string, field: string): Buffer {
  if (!isValidHex(hex)) {
    throw new Error(`${field}: invalid hex`);
  }
  return Buffer.from(hex, "hex");
}

function aesGcmEncrypt(
  key: Buffer,
  plaintext: Buffer,
  aad?: Buffer
): { nonce: Buffer; ciphertext: Buffer; tag: Buffer } {
  if (key.length !== KEY_BYTES) {
    throw new Error("key: invalid length");
  }

  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  if (aad) {
    cipher.setAAD(aad);
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return { nonce, ciphertext, tag };
}

function aesGcmDecrypt(
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
  aad?: Buffer
): Buffer {
  if (key.length !== KEY_BYTES) {
    throw new Error("key: invalid length");
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new Error("nonce: invalid length");
  }
  if (tag.length !== TAG_BYTES) {
    throw new Error("tag: invalid length");
  }

  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    if (aad) {
      decipher.setAAD(aad);
    }
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("decryption failed");
  }
}

export function parseMasterKeyHex(masterKeyHex: string): Buffer {
  assertHexLength(masterKeyHex, KEY_BYTES, "master key");
  return Buffer.from(masterKeyHex, "hex");
}

export function encryptTransaction(input: {
  partyId: string;
  payload: unknown;
  masterKeyHex: string;
}): TxSecureRecord {
  const { partyId, payload, masterKeyHex } = input;

  if (!partyId || typeof partyId !== "string") {
    throw new Error("partyId is required");
  }

  const masterKey = parseMasterKeyHex(masterKeyHex);
  const dek = randomBytes(KEY_BYTES);
  const payloadJson = JSON.stringify(payload);
  if (payloadJson === undefined) {
    throw new Error("payload is not JSON-serializable");
  }
  const payloadBuffer = Buffer.from(payloadJson, "utf8");

  const id = randomUUID();
  const createdAt = new Date().toISOString();
  const alg = "AES-256-GCM" as const;
  const mk_version = 1 as const;
  const aad = Buffer.from(
    JSON.stringify({ id, partyId, createdAt, alg, mk_version }),
    "utf8"
  );

  const payloadEncrypted = aesGcmEncrypt(dek, payloadBuffer, aad);
  const wrappedDek = aesGcmEncrypt(masterKey, dek, aad);

  return {
    id,
    partyId,
    createdAt,
    payload_nonce: payloadEncrypted.nonce.toString("hex"),
    payload_ct: payloadEncrypted.ciphertext.toString("hex"),
    payload_tag: payloadEncrypted.tag.toString("hex"),
    dek_wrap_nonce: wrappedDek.nonce.toString("hex"),
    dek_wrapped: wrappedDek.ciphertext.toString("hex"),
    dek_wrap_tag: wrappedDek.tag.toString("hex"),
    alg,
    mk_version,
  };
}

export function validateRecordShape(record: TxSecureRecord): void {
  if (!record.id || typeof record.id !== "string") {
    throw new Error("id is required");
  }
  if (!record.partyId || typeof record.partyId !== "string") {
    throw new Error("partyId is required");
  }
  if (!record.createdAt || typeof record.createdAt !== "string") {
    throw new Error("createdAt is required");
  }
  if (Number.isNaN(Date.parse(record.createdAt))) {
    throw new Error("createdAt: invalid format");
  }
  if (record.alg !== "AES-256-GCM") {
    throw new Error("unsupported algorithm");
  }
  if (record.mk_version !== 1) {
    throw new Error("unsupported master key version");
  }

  assertHexLength(record.payload_nonce, NONCE_BYTES, "payload_nonce");
  assertHexLength(record.payload_tag, TAG_BYTES, "payload_tag");
  assertHexLength(record.dek_wrap_nonce, NONCE_BYTES, "dek_wrap_nonce");
  assertHexLength(record.dek_wrap_tag, TAG_BYTES, "dek_wrap_tag");
  fromHex(record.payload_ct, "payload_ct");
  fromHex(record.dek_wrapped, "dek_wrapped");
}

export function decryptTransaction(input: {
  record: TxSecureRecord;
  masterKeyHex: string;
}): unknown {
  const { record, masterKeyHex } = input;
  validateRecordShape(record);

  const masterKey = parseMasterKeyHex(masterKeyHex);
  const aad = Buffer.from(
    JSON.stringify({
      id: record.id,
      partyId: record.partyId,
      createdAt: record.createdAt,
      alg: record.alg,
      mk_version: record.mk_version,
    }),
    "utf8"
  );
  const dek = aesGcmDecrypt(
    masterKey,
    fromHex(record.dek_wrap_nonce, "dek_wrap_nonce"),
    fromHex(record.dek_wrapped, "dek_wrapped"),
    fromHex(record.dek_wrap_tag, "dek_wrap_tag"),
    aad
  );

  if (dek.length !== KEY_BYTES) {
    throw new Error("decryption failed");
  }

  const plaintext = aesGcmDecrypt(
    dek,
    fromHex(record.payload_nonce, "payload_nonce"),
    fromHex(record.payload_ct, "payload_ct"),
    fromHex(record.payload_tag, "payload_tag"),
    aad
  );

  try {
    return JSON.parse(plaintext.toString("utf8"));
  } catch {
    throw new Error("decryption failed");
  }
}
