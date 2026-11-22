import { createHash, createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";

export const RELEASE_PROVENANCE_PREDICATE = "https://chainproof.dev/attestations/release-provenance/v1";
export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";

export interface DsseEnvelope {
  payloadType: string;
  payload: string;
  signatures: Array<{ keyid: string; sig: string }>;
}
export interface ExpectedReleaseProvenance {
  artifactSha256: string;
  sourceRepository: string;
  sourceCommitSha: string;
  builderIdentity: string;
  buildRunUrl: string;
}
export interface TrustedAttestationKey {
  publicKeyPem: string;
  algorithm: "ed25519";
}
export interface AttestationVerification {
  status: "verified" | "failed" | "untrusted_key" | "not_provided";
  keyId: string | null;
  envelopeSha256: string | null;
  reasons: string[];
}
type TrustedKeys = Record<string, TrustedAttestationKey>;

function pae(payloadType: string, payload: Buffer): Buffer {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} ${type.toString("utf8")} ${payload.length} `, "utf8"),
    payload
  ]);
}
function decodeCanonicalBase64(value: string, maxBytes: number): Buffer | null {
  if (!value || value.length > Math.ceil(maxBytes * 4 / 3) + 8 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  const decoded = Buffer.from(value, "base64");
  return decoded.length <= maxBytes && decoded.toString("base64") === value ? decoded : null;
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function normalizeRepository(value: string): string {
  return value.replace(/\.git$/i, "").replace(/\/$/, "").toLowerCase();
}

export function verifyReleaseAttestation(
  envelope: DsseEnvelope | undefined,
  expected: ExpectedReleaseProvenance,
  trustedKeys: TrustedKeys
): AttestationVerification {
  if (!envelope) return { status: "not_provided", keyId: null, envelopeSha256: null, reasons: ["A signed DSSE attestation was not supplied."] };
  const fail = (reason: string, status: AttestationVerification["status"] = "failed", keyId: string | null = null, digest: string | null = null): AttestationVerification =>
    ({ status, keyId, envelopeSha256: digest, reasons: [reason] });
  if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) return fail("Unsupported DSSE payload type.");
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length < 1 || envelope.signatures.length > 5) return fail("The DSSE envelope must contain between one and five signatures.");
  const payload = decodeCanonicalBase64(envelope.payload, 256 * 1024);
  if (!payload) return fail("The DSSE payload is not valid bounded canonical base64.");
  const envelopeSha256 = createHash("sha256").update(JSON.stringify([envelope.payloadType, envelope.payload, envelope.signatures])).digest("hex");
  let statement: unknown;
  try { statement = JSON.parse(payload.toString("utf8")); }
  catch { return fail("The DSSE payload is not valid JSON.", "failed", null, envelopeSha256); }
  if (!isRecord(statement) || statement._type !== "https://in-toto.io/Statement/v1" ||
      statement.predicateType !== RELEASE_PROVENANCE_PREDICATE || !Array.isArray(statement.subject) ||
      !isRecord(statement.predicate)) {
    return fail("The attestation is not a supported ChainProof in-toto release-provenance statement.", "failed", null, envelopeSha256);
  }
  const subjectMatches = statement.subject.some(subject =>
    isRecord(subject) && isRecord(subject.digest) &&
    typeof subject.digest.sha256 === "string" &&
    subject.digest.sha256.toLowerCase() === expected.artifactSha256.toLowerCase()
  );
  if (!subjectMatches) return fail("The attestation subject does not match the release artifact SHA-256.", "failed", null, envelopeSha256);
  const predicate = statement.predicate;
  const claimsMatch =
    predicate.sourceRepository === expected.sourceRepository &&
    predicate.sourceCommitSha === expected.sourceCommitSha &&
    predicate.builderIdentity === expected.builderIdentity &&
    predicate.buildRunUrl === expected.buildRunUrl;
  if (!claimsMatch) return fail("The signed provenance claims do not match the release request.", "failed", null, envelopeSha256);

  const paeBytes = pae(envelope.payloadType, payload);
  const seen = new Set<string>();
  let untrustedKeySeen = false;
  for (const signature of envelope.signatures) {
    if (!isRecord(signature) || typeof signature.keyid !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(signature.keyid) ||
        typeof signature.sig !== "string" || seen.has(signature.keyid)) continue;
    seen.add(signature.keyid);
    const trusted = trustedKeys[signature.keyid];
    if (!trusted) { untrustedKeySeen = true; continue; }
    const signatureBytes = decodeCanonicalBase64(signature.sig, 1024);
    if (!signatureBytes) continue;
    try {
      const publicKey: KeyObject = createPublicKey(trusted.publicKeyPem);
      if (publicKey.asymmetricKeyType !== "ed25519" || trusted.algorithm !== "ed25519") continue;
      if (verifySignature(null, paeBytes, publicKey, signatureBytes)) {
        return { status: "verified", keyId: signature.keyid, envelopeSha256, reasons: [] };
      }
    } catch { /* Invalid configured key material fails closed. */ }
  }
  return fail(
    untrustedKeySeen ? "No signature matched a configured trusted key." : "No valid Ed25519 signature was found.",
    untrustedKeySeen ? "untrusted_key" : "failed",
    null,
    envelopeSha256
  );
}

export function parseTrustedAttestationKeys(serialized: string | undefined): Record<string, TrustedAttestationKey> {
  if (!serialized) return {};
  const parsed: unknown = JSON.parse(serialized);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Attestation trust roots must be a JSON object.");
  const entries = Object.entries(parsed);
  if (entries.length > 100) throw new Error("At most 100 attestation trust roots may be configured.");
  const result: Record<string, TrustedAttestationKey> = {};
  for (const [keyId, value] of entries) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyId) || !isRecord(value) ||
        value.algorithm !== "ed25519" || typeof value.publicKeyPem !== "string" ||
        !value.publicKeyPem.includes("BEGIN PUBLIC KEY")) {
      throw new Error("Each trust root requires a valid key ID, Ed25519 algorithm, and PEM public key.");
    }
    result[keyId] = { algorithm: "ed25519", publicKeyPem: value.publicKeyPem };
  }
  return result;
}
