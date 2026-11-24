import { createHash } from "node:crypto";
import { verify } from "sigstore";

export type VerificationFailureCode =
  | "policy_not_configured" | "invalid_bundle" | "signature_invalid"
  | "provenance_invalid" | "artifact_digest_mismatch" | "builder_not_allowed";
export class ProvenanceVerificationError extends Error {
  constructor(public readonly code: VerificationFailureCode) { super(code); this.name = "ProvenanceVerificationError"; }
}
interface ProvenanceSummary {
  artifactDigest: string;
  certificateIssuer: string;
  certificateIdentity: string;
  predicateType: string;
  buildType: string;
  builderId: string;
  sourceRepository?: string;
  sourceCommit?: string;
  invocationId?: string;
}
function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function decodeBase64(value: unknown, maxBytes: number): Buffer {
  if (typeof value !== "string" || value.length === 0 || value.length > Math.ceil(maxBytes * 4 / 3) + 8 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new ProvenanceVerificationError("invalid_bundle");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.length > maxBytes || decoded.toString("base64") !== value) {
    throw new ProvenanceVerificationError("invalid_bundle");
  }
  return decoded;
}

/**
 * Verifies a Sigstore DSSE bundle using the public-good trust root, then checks
 * the signed SLSA provenance statement against the supplied artifact bytes.
 * Trust policy is server-side only; clients cannot choose trusted identities.
 */
export async function verifySlsaProvenance(artifactBase64: string, bundle: unknown): Promise<ProvenanceSummary> {
  const issuer = process.env.SIGSTORE_CERTIFICATE_ISSUER?.trim();
  const identity = process.env.SIGSTORE_CERTIFICATE_IDENTITY?.trim();
  const allowedBuilders = (process.env.SLSA_ALLOWED_BUILDERS ?? "").split(",").map((v) => v.trim()).filter(Boolean);
  if (!issuer || !identity || allowedBuilders.length === 0) {
    throw new ProvenanceVerificationError("policy_not_configured");
  }
  const artifact = decodeBase64(artifactBase64, 1024 * 1024);
  if (!isRecord(bundle) || Buffer.byteLength(JSON.stringify(bundle), "utf8") > 512 * 1024 ||
      !isRecord(bundle.dsseEnvelope) || typeof bundle.dsseEnvelope.payload !== "string") {
    throw new ProvenanceVerificationError("invalid_bundle");
  }
  try {
    await verify(bundle as never, undefined, {
      certificateIssuer: issuer,
      certificateIdentity: identity
    } as never);
  } catch {
    throw new ProvenanceVerificationError("signature_invalid");
  }

  let statement: unknown;
  try {
    statement = JSON.parse(decodeBase64(bundle.dsseEnvelope.payload, 512 * 1024).toString("utf8"));
  } catch (error) {
    if (error instanceof ProvenanceVerificationError) throw error;
    throw new ProvenanceVerificationError("provenance_invalid");
  }
  if (!isRecord(statement) || statement._type !== "https://in-toto.io/Statement/v1" ||
      statement.predicateType !== "https://slsa.dev/provenance/v1" ||
      !Array.isArray(statement.subject) || !isRecord(statement.predicate)) {
    throw new ProvenanceVerificationError("provenance_invalid");
  }
  const artifactDigest = createHash("sha256").update(artifact).digest("hex");
  const subjectMatches = statement.subject.some((subject: unknown) =>
    isRecord(subject) && isRecord(subject.digest) &&
    typeof subject.digest.sha256 === "string" && subject.digest.sha256.toLowerCase() === artifactDigest
  );
  if (!subjectMatches) throw new ProvenanceVerificationError("artifact_digest_mismatch");

  const buildDefinition = statement.predicate.buildDefinition;
  const runDetails = statement.predicate.runDetails;
  const builderId = isRecord(runDetails) && isRecord(runDetails.builder) && typeof runDetails.builder.id === "string"
    ? runDetails.builder.id : "";
  const buildType = isRecord(buildDefinition) && typeof buildDefinition.buildType === "string"
    ? buildDefinition.buildType : "";
  if (!builderId || !buildType) throw new ProvenanceVerificationError("provenance_invalid");
  if (!allowedBuilders.includes(builderId)) throw new ProvenanceVerificationError("builder_not_allowed");

  const external = isRecord(buildDefinition) && isRecord(buildDefinition.externalParameters)
    ? buildDefinition.externalParameters : {};
  const source = isRecord(external.source) ? external.source : {};
  const resolved = isRecord(buildDefinition) && Array.isArray(buildDefinition.resolvedDependencies)
    ? buildDefinition.resolvedDependencies : [];
  const repository = typeof source.uri === "string" ? source.uri
    : typeof source.repository === "string" ? source.repository : undefined;
  const commit = typeof source.digest?.gitCommit === "string" ? source.digest.gitCommit
    : typeof source.revision === "string" ? source.revision
    : resolved.find((item: unknown) => isRecord(item) && isRecord(item.digest) && typeof item.digest.gitCommit === "string")?.digest.gitCommit;
  const invocationId = isRecord(runDetails) && isRecord(runDetails.metadata) && typeof runDetails.metadata.invocationId === "string"
    ? runDetails.metadata.invocationId : undefined;

  return {
    artifactDigest,
    certificateIssuer: issuer,
    certificateIdentity: identity,
    predicateType: statement.predicateType,
    buildType,
    builderId,
    ...(repository ? { sourceRepository: repository.slice(0, 1000) } : {}),
    ...(commit ? { sourceCommit: commit.slice(0, 200) } : {}),
    ...(invocationId ? { invocationId: invocationId.slice(0, 1000) } : {})
  };
}
