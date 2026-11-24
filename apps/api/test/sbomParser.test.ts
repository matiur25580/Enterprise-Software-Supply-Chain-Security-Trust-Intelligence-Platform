import { describe, expect, it } from "vitest";
import { parseSbomDocument, SbomValidationError } from "../src/services/sbomParser";

describe("SBOM document normalization", () => {
  it("normalizes CycloneDX 1.6 metadata and package URLs", () => {
    const parsed = parseSbomDocument({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: { component: { name: "payments-api", version: "2.4.0" } },
      components: [{ type: "library", name: "express", version: "4.21.2", "bom-ref": "pkg:express", purl: "pkg:npm/express@4.21.2" }],
      dependencies: [{ ref: "pkg:express", dependsOn: ["pkg:lodash"] }]
    });
    expect(parsed.format).toBe("cyclonedx");
    expect(parsed.documentName).toBe("payments-api");
    expect(parsed.componentCount).toBe(1);
    expect(parsed.normalizedComponents[0]).toMatchObject({ name: "express", version: "4.21.2", bomRef: "pkg:express", purl: "pkg:npm/express@4.21.2" });
    expect(parsed.normalizedDependencies).toEqual([{ from: "pkg:express", to: "pkg:lodash", relationshipType: "dependsOn" }]);
    expect(parsed.documentDigest).toMatch(/^[a-f0-9]{64}$/);
  });

  it("normalizes SPDX 2.3 package inventory", () => {
    const parsed = parseSbomDocument({
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: "billing-service",
      documentNamespace: "https://example.invalid/spdx/billing-service",
      creationInfo: { created: "2026-11-24T00:00:00Z", creators: ["Tool: ChainProof-0.1.0"] },
      packages: [{ name: "lodash", SPDXID: "SPDXRef-Package", downloadLocation: "NOASSERTION", versionInfo: "4.17.21", externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:npm/lodash@4.17.21" }] }],
      relationships: [{ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-Package" }]
    });
    expect(parsed.format).toBe("spdx");
    expect(parsed.documentName).toBe("billing-service");
    expect(parsed.normalizedComponents[0]).toMatchObject({ name: "lodash", version: "4.17.21", bomRef: "SPDXRef-Package", purl: "pkg:npm/lodash@4.17.21" });
    expect(parsed.normalizedDependencies).toEqual([{ from: "SPDXRef-DOCUMENT", to: "SPDXRef-Package", relationshipType: "DESCRIBES" }]);
  });

  it("rejects unsupported versions and malformed package URLs", () => {
    expect(() => parseSbomDocument({ bomFormat: "CycloneDX", specVersion: "1.3", components: [] })).toThrow(SbomValidationError);
    expect(() => parseSbomDocument({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ name: "bad", purl: "https://example.com" }] })).toThrow(/package-url/);
  });

  it("rejects structurally invalid documents using the official schema", () => {
    expect(() => parseSbomDocument({ bomFormat: "CycloneDX", specVersion: "1.6", version: "not-an-integer", components: [] })).toThrow(/Official cyclonedx 1.6 JSON schema validation failed/);
  });

  it("rejects duplicate normalized component identities", () => {
    expect(() => parseSbomDocument({
      bomFormat: "CycloneDX", specVersion: "1.6",
      components: [{ name: "lib", version: "1.0" }, { name: "LIB", version: "1.0" }]
    })).toThrow(/Duplicate component identity/);
  });
});
