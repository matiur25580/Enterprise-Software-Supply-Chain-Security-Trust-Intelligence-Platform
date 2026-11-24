import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
vi.mock("sigstore", () => ({ verify: vi.fn() }));
import { verify } from "sigstore";
import { ProvenanceVerificationError, verifyArtifactSignature, verifySlsaProvenance } from "../src/services/provenanceVerifier";

const sigstoreVerify = vi.mocked(verify);
const artifact = Buffer.from("chainproof-test-artifact");
const artifactBase64 = artifact.toString("base64");
const digest = createHash("sha256").update(artifact).digest("hex");
function makeBundle(subjectDigest = digest) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    predicateType: "https://slsa.dev/provenance/v1",
    subject: [{ name: "release.tar.gz", digest: { sha256: subjectDigest } }],
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/actions/runner",
        externalParameters: { source: { uri: "https://github.com/acme/project", digest: { gitCommit: "abc123" } } },
        resolvedDependencies: []
      },
      runDetails: { builder: { id: "https://github.com/acme/project/.github/workflows/release.yml@refs/heads/main" }, metadata: { invocationId: "run-42" } }
    }
  };
  return { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString("base64") } };
}
describe("Sigstore SLSA provenance verifier", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.SIGSTORE_CERTIFICATE_ISSUER = "https://token.actions.githubusercontent.com";
    process.env.SIGSTORE_CERTIFICATE_IDENTITY = "https://github.com/acme/project/.github/workflows/release.yml@refs/heads/main";
    process.env.SLSA_ALLOWED_BUILDERS = "https://github.com/acme/project/.github/workflows/release.yml@refs/heads/main";
  });
  it("verifies a Cosign detached signature over the exact artifact bytes", async () => {
    sigstoreVerify.mockResolvedValue({} as never);
    const result = await verifyArtifactSignature(artifactBase64, { messageSignature: { signature: "dGVzdA==" } });
    expect(sigstoreVerify).toHaveBeenCalledWith(expect.any(Object), artifact, {
      certificateIssuer: process.env.SIGSTORE_CERTIFICATE_ISSUER,
      certificateIdentity: process.env.SIGSTORE_CERTIFICATE_IDENTITY
    });
    expect(result).toEqual({
      artifactDigest: digest,
      certificateIssuer: process.env.SIGSTORE_CERTIFICATE_ISSUER,
      certificateIdentity: process.env.SIGSTORE_CERTIFICATE_IDENTITY
    });
  });
  it("verifies signature policy and matches the SLSA subject digest to artifact bytes", async () => {
    sigstoreVerify.mockResolvedValue({} as never);
    const result = await verifySlsaProvenance(artifactBase64, makeBundle());
    expect(sigstoreVerify).toHaveBeenCalledWith(expect.any(Object), undefined, {
      certificateIssuer: process.env.SIGSTORE_CERTIFICATE_ISSUER,
      certificateIdentity: process.env.SIGSTORE_CERTIFICATE_IDENTITY
    });
    expect(result).toMatchObject({
      artifactDigest: digest,
      predicateType: "https://slsa.dev/provenance/v1",
      builderId: process.env.SLSA_ALLOWED_BUILDERS,
      sourceRepository: "https://github.com/acme/project",
      sourceCommit: "abc123",
      invocationId: "run-42"
    });
  });
  it("rejects a provenance subject that does not match artifact bytes", async () => {
    sigstoreVerify.mockResolvedValue({} as never);
    await expect(verifySlsaProvenance(artifactBase64, makeBundle("0".repeat(64))))
      .rejects.toMatchObject({ code: "artifact_digest_mismatch" });
  });
  it("rejects a validly signed but unapproved builder", async () => {
    sigstoreVerify.mockResolvedValue({} as never);
    process.env.SLSA_ALLOWED_BUILDERS = "https://trusted.example/builder";
    await expect(verifySlsaProvenance(artifactBase64, makeBundle()))
      .rejects.toMatchObject({ code: "builder_not_allowed" });
  });
  it("fails closed when server-side identity policy is missing", async () => {
    delete process.env.SIGSTORE_CERTIFICATE_IDENTITY;
    await expect(verifySlsaProvenance(artifactBase64, makeBundle()))
      .rejects.toMatchObject({ code: "policy_not_configured" });
    expect(sigstoreVerify).not.toHaveBeenCalled();
  });
  it("rejects a bundle whose Sigstore signature cannot be verified", async () => {
    sigstoreVerify.mockRejectedValue(new Error("invalid signature"));
    await expect(verifySlsaProvenance(artifactBase64, makeBundle()))
      .rejects.toMatchObject({ code: "signature_invalid" });
  });
});
