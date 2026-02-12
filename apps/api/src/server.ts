import Fastify from "fastify";
import cors from "@fastify/cors";
import "dotenv/config";
import {
  decryptTransaction,
  encryptTransaction,
  type TxSecureRecord,
} from "@repo/crypto";

type EncryptBody = {
  partyId: string;
  payload: unknown;
};

const app = Fastify({ logger: true });
const store = new Map<string, TxSecureRecord>();

await app.register(cors, {
  origin: true,
});

function getMasterKeyHex(): string {
  const key = process.env.MASTER_KEY_HEX;
  if (!key) {
    throw new Error("MASTER_KEY_HEX is not set");
  }
  return key;
}

function isRecordInput(body: unknown): body is EncryptBody {
  if (!body || typeof body !== "object") {
    return false;
  }

  const candidate = body as Partial<EncryptBody>;
  return typeof candidate.partyId === "string" && "payload" in candidate;
}

function normalizeError(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return "Unknown error";
}

app.get("/", async () => ({ status: "api running" }));

app.post("/tx/encrypt", async (request, reply) => {
  if (!isRecordInput(request.body)) {
    return reply.status(400).send({
      error: "Invalid body. Expected { partyId: string, payload: unknown }",
    });
  }

  try {
    const record = encryptTransaction({
      partyId: request.body.partyId,
      payload: request.body.payload,
      masterKeyHex: getMasterKeyHex(),
    });

    store.set(record.id, record);
    return reply.status(201).send(record);
  } catch (err) {
    return reply.status(400).send({ error: normalizeError(err) });
  }
});

app.get<{ Params: { id: string } }>("/tx/:id", async (request, reply) => {
  const record = store.get(request.params.id);
  if (!record) {
    return reply.status(404).send({ error: "Record not found" });
  }

  return reply.send(record);
});

app.post<{ Params: { id: string } }>(
  "/tx/:id/decrypt",
  async (request, reply) => {
    const record = store.get(request.params.id);
    if (!record) {
      return reply.status(404).send({ error: "Record not found" });
    }

    try {
      const payload = decryptTransaction({
        record,
        masterKeyHex: getMasterKeyHex(),
      });

      return reply.send({
        id: record.id,
        partyId: record.partyId,
        payload,
      });
    } catch (err) {
      return reply.status(400).send({ error: normalizeError(err) });
    }
  }
);

const port = Number(process.env.PORT ?? "3001");
const host = process.env.HOST ?? "0.0.0.0";

const start = async () => {
  try {
    await app.listen({ port, host });
    app.log.info(`API running on http://${host}:${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

await start();
