import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";

export interface ReleasePassportPayload {
  schemaVersion: "chainproof.release-trust-passport/v1";
  passportId: string;
  issuedAt: string;
  artifact: { sha256: string };
  sbom: { recordId: string; format?: string; componentCount?: number };
  vulnerability: null | {
    source: "OSV";
    scannedAt: string;
    scannedPackages: number;
    vulnerablePackages: number;
    findingCount: number;
    advisories: Array<{ id: string; severity: string; cvssScore?: number; epssScore?: number; isKnownExploited: boolean }>;
  };
  provenance: null | {
    verificationType: string;
    verifiedAt: string;
    certificateIssuer?: string;
    certificateIdentity?: string;
    builderId?: string;
    sourceRepository?: string;
    sourceCommit?: string;
  };
  policy: {
    evaluationId: string;
    version: string;
    outcome: "pass" | "warn" | "block";
    riskScore: number;
    evaluatedAt: string;
    checks: Array<{ id: string; status: "pass" | "warn" | "block"; message: string }>;
  };
}
export interface SignedReleasePassport {
  algorithm: "Ed25519";
  keyId: string;
  publicKey: string;
  payload: ReleasePassportPayload;
  signature: string;
}

function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).filter((key) => record[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

function signingBytes(passport: Pick<SignedReleasePassport, "algorithm" | "keyId" | "payload">): Buffer {
  return Buffer.from(canonicalJson({
    algorithm: passport.algorithm,
    keyId: passport.keyId,
    payload: passport.payload
  }), "utf8");
}

function publicKeyFingerprint(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

export function createSignedReleasePassport(payload: ReleasePassportPayload, privateKeyPem: string): SignedReleasePassport {
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Release passport signing key must use Ed25519.");
  const publicKey = createPublicKey(privateKey);
  const keyId = publicKeyFingerprint(publicKey);
  const passport = {
    algorithm: "Ed25519" as const,
    keyId,
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    payload
  };
  const signature = sign(null, signingBytes(passport), privateKey).toString("base64");
  return { ...passport, signature };
}

export function verifySignedReleasePassport(passport: SignedReleasePassport): boolean {
  try {
    if (passport.algorithm !== "Ed25519" || !/^[a-f0-9]{64}$/.test(passport.keyId)) return false;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(passport.signature)) return false;
    const publicKey = createPublicKey(passport.publicKey);
    if (publicKey.asymmetricKeyType !== "ed25519" || publicKeyFingerprint(publicKey) !== passport.keyId) return false;
    return verify(null, signingBytes(passport), publicKey, Buffer.from(passport.signature, "base64"));
  } catch {
    return false;
  }
}
