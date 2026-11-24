import { Router } from "express";
import { rateLimit } from "express-rate-limit";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { z } from "zod";
import { authorize } from "../middleware/authorize";
import { ReleasePassportSigner } from "../models/ReleasePassportSigner";

export const signerRouter = Router();
const limiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false });

function configuredSigner() {
  const privatePem = process.env.RELEASE_PASSPORT_PRIVATE_KEY?.replace(/\\n/g, "\n").trim();
  if (!privatePem) throw new Error("RELEASE_PASSPORT_PRIVATE_KEY is not configured");
  const privateKey = createPrivateKey(privatePem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Release passport signing key must use Ed25519.");
  const publicKey = createPublicKey(privateKey);
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyId = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  return { keyId, publicKey: publicKeyPem };
}

signerRouter.get("/release-signers", limiter, authorize("platform-admin", "security-analyst", "developer", "auditor"), async (request, response) => {
  try {
    const limit = Math.min(Math.max(Number(request.query.limit) || 50, 1), 100);
    const items = await ReleasePassportSigner.find({ tenantId: request.auth!.tenantId })
      .select({ keyId: 1, algorithm: 1, status: 1, activatedAt: 1, activatedBy: 1, rotatedFrom: 1, retiredAt: 1, revokedAt: 1, revokedBy: 1, revocationReason: 1 })
      .sort({ activatedAt: -1 }).limit(limit).lean();
    response.status(200).json({ items, count: items.length, limit });
  } catch {
    response.status(500).json({ error: "Unable to load trusted release signers" });
  }
});

/**
 * Activate the Ed25519 public key derived from the server-side private key.
 * The private key is never accepted from or returned to the caller.
 */
signerRouter.post("/release-signers/rotate", limiter, authorize("platform-admin"), async (request, response) => {
  const input = z.object({ expectedCurrentKeyId: z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict().safeParse(request.body);
  if (!input.success) { response.status(400).json({ error: "Invalid signer rotation request" }); return; }
  try {
    const { keyId, publicKey } = configuredSigner();
    const tenantId = request.auth!.tenantId;
    const current: any = await ReleasePassportSigner.findOne({ tenantId, status: "active" }).sort({ activatedAt: -1 }).lean();
    if (current?.keyId === keyId) {
      response.status(409).json({ error: "The configured signing key is already active", keyId });
      return;
    }
    if (input.data.expectedCurrentKeyId && current?.keyId !== input.data.expectedCurrentKeyId) {
      response.status(409).json({ error: "Active signer changed; reload signer inventory before rotating." });
      return;
    }
    const previouslyRevoked = await ReleasePassportSigner.findOne({ tenantId, keyId, status: "revoked" }).lean();
    if (previouslyRevoked) {
      response.status(409).json({ error: "A revoked signing key cannot be reactivated." });
      return;
    }
    const now = new Date();
    await ReleasePassportSigner.updateMany({ tenantId, status: "active" }, { $set: { status: "retired", retiredAt: now } });
    const signer = await ReleasePassportSigner.findOneAndUpdate(
      { tenantId, keyId },
      { $set: { algorithm: "Ed25519", publicKey, status: "active", activatedAt: now, activatedBy: request.auth!.userId, rotatedFrom: current?.keyId, retiredAt: null, revokedAt: null, revokedBy: null, revocationReason: null } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true }
    ).select({ keyId: 1, algorithm: 1, status: 1, activatedAt: 1, activatedBy: 1, rotatedFrom: 1 }).lean();
    response.status(200).json({ signer, message: "Signer activated. Previous active signer is retained as retired for historical verification." });
  } catch (error) {
    response.status(503).json({ error: error instanceof Error && error.message.includes("RELEASE_PASSPORT_PRIVATE_KEY") ? error.message : "Unable to rotate release passport signer" });
  }
});

const revokeInput = z.object({
  keyId: z.string().regex(/^[a-f0-9]{64}$/),
  reason: z.string().trim().min(10).max(1000)
}).strict();

signerRouter.post("/release-signers/revoke", limiter, authorize("platform-admin"), async (request, response) => {
  const parsed = revokeInput.safeParse(request.body);
  if (!parsed.success) { response.status(400).json({ error: "A valid keyId and 10–1000 character revocation reason are required." }); return; }
  try {
    const signer = await ReleasePassportSigner.findOneAndUpdate(
      { tenantId: request.auth!.tenantId, keyId: parsed.data.keyId, status: { $in: ["active", "retired"] } },
      { $set: { status: "revoked", revokedAt: new Date(), revokedBy: request.auth!.userId, revocationReason: parsed.data.reason } },
      { new: true, runValidators: true }
    ).select({ keyId: 1, status: 1, revokedAt: 1, revokedBy: 1, revocationReason: 1 }).lean();
    if (!signer) { response.status(404).json({ error: "Trusted signer not found or already revoked" }); return; }
    response.status(200).json({ signer, message: "Signer revoked. Consumers must treat signatures from this key as untrusted." });
  } catch {
    response.status(500).json({ error: "Unable to revoke release passport signer" });
  }
});
