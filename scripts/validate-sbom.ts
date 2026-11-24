import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseSbomDocument, SbomValidationError } from "../apps/api/src/services/sbomParser";

function argument(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main(): Promise<void> {
  // Keep the file path explicit so a developer can validate a local export without uploading it.
  const file = argument("--file");
  if (!file || process.argv.includes("--help")) {
    console.log("Usage: npm run sbom:validate -- --file ./path/to/bom.json");
    console.log("Validates CycloneDX 1.4/1.5/1.6 or SPDX 2.3 JSON against vendored upstream schemas.");
    process.exitCode = file ? 0 : 1;
    return;
  }

  try {
    // Read the SBOM locally; this command never sends the document to a remote service.
    const source = await readFile(resolve(file), "utf8");
    const document: unknown = JSON.parse(source);
    const parsed = parseSbomDocument(document);
    console.log(JSON.stringify({
      valid: true,
      format: parsed.format,
      version: parsed.formatVersion,
      documentName: parsed.documentName,
      componentCount: parsed.componentCount,
      dependencyRelationshipCount: parsed.normalizedDependencies.length,
      sha256OfJsonSerialization: parsed.documentDigest
    }, null, 2));
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.error("Invalid JSON: " + error.message);
    } else if (error instanceof SbomValidationError) {
      console.error("SBOM validation failed: " + error.message);
    } else {
      console.error("Unable to validate SBOM: " + (error instanceof Error ? error.message : "unknown error"));
    }
    process.exitCode = 2;
  }
}

void main();
