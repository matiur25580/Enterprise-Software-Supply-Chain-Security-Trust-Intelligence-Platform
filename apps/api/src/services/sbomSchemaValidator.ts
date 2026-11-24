import Ajv, { type AnySchema, type ValidateFunction } from "ajv";
import addFormats from "ajv-formats";
import cyclonedx14 from "../schemas/sbom/cyclonedx-1.4.schema.json";
import cyclonedx15 from "../schemas/sbom/cyclonedx-1.5.schema.json";
import cyclonedx16 from "../schemas/sbom/cyclonedx-1.6.schema.json";
import cyclonedxSpdx from "../schemas/sbom/cyclonedx-spdx.schema.json";
import cyclonedxJsf from "../schemas/sbom/cyclonedx-jsf-0.82.schema.json";
import spdx23 from "../schemas/sbom/spdx-2.3.schema.json";

export type SbomSchemaFormat = "cyclonedx" | "spdx";
export interface SbomSchemaValidationResult {
  valid: boolean;
  format: SbomSchemaFormat;
  version: string;
  errors: string[];
}

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 50_000;
const MAX_COLLECTION_ITEMS = 10_000;

/** Bound untrusted JSON traversal before invoking recursive JSON Schema validation. */
function checkJsonComplexity(value: unknown): string | undefined {
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let visited = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    visited += 1;
    if (visited > MAX_JSON_NODES) return "SBOM document exceeds the JSON node limit";
    if (current.depth > MAX_JSON_DEPTH) return "SBOM document exceeds the maximum JSON nesting depth";
    if (Array.isArray(current.value)) {
      if (current.value.length > MAX_COLLECTION_ITEMS) return "SBOM array exceeds the item limit";
      for (const child of current.value) pending.push({ value: child, depth: current.depth + 1 });
    } else if (typeof current.value === "object" && current.value !== null) {
      const entries = Object.values(current.value as Record<string, unknown>);
      if (entries.length > MAX_COLLECTION_ITEMS) return "SBOM object exceeds the property limit";
      for (const child of entries) pending.push({ value: child, depth: current.depth + 1 });
    }
  }
  return undefined;
}

// Stop at the first schema violation; the request path is bounded by node/depth limits above.
const ajv = new Ajv({ allErrors: false, strict: false, validateFormats: true });
addFormats(ajv);
// CycloneDX schemas use the IRI-reference format from RFC 3987, which ajv-formats does not register.
ajv.addFormat("iri-reference", {
  type: "string",
  validate: (value: string) => {
    if (/[\u0000-\u0020\u007f]/.test(value)) return false;
    try {
      new URL(value, "https://chainproof.invalid/");
      return true;
    } catch {
      return false;
    }
  }
});
ajv.addSchema(cyclonedxSpdx as AnySchema);
ajv.addSchema(cyclonedxJsf as AnySchema);

const validateCycloneDx14 = ajv.compile(cyclonedx14 as AnySchema);
const validateCycloneDx15 = ajv.compile(cyclonedx15 as AnySchema);
const validateCycloneDx16 = ajv.compile(cyclonedx16 as AnySchema);
const validateSpdx23 = ajv.compile(spdx23 as AnySchema);

function validationErrors(validator: ValidateFunction): string[] {
  return (validator.errors ?? []).slice(0, 12).map((error) =>
    `${error.instancePath || "/"} ${error.message ?? "does not match the official schema"}`
  );
}

export function validateSbomDocumentSchema(document: unknown): SbomSchemaValidationResult {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return { valid: false, format: "cyclonedx", version: "unknown", errors: ["SBOM document must be a JSON object"] };
  }
  const complexityError = checkJsonComplexity(document);
  if (complexityError) {
    return { valid: false, format: "cyclonedx", version: "unknown", errors: [complexityError] };
  }

  const candidate = document as Record<string, unknown>;
  if (candidate.bomFormat === "CycloneDX" && typeof candidate.specVersion === "string") {
    const version = candidate.specVersion;
    if (version === "1.4") {
      const valid = validateCycloneDx14(document);
      return { valid: Boolean(valid), format: "cyclonedx", version, errors: valid ? [] : validationErrors(validateCycloneDx14) };
    }
    if (version === "1.5") {
      const valid = validateCycloneDx15(document);
      return { valid: Boolean(valid), format: "cyclonedx", version, errors: valid ? [] : validationErrors(validateCycloneDx15) };
    }
    if (version === "1.6") {
      const valid = validateCycloneDx16(document);
      return { valid: Boolean(valid), format: "cyclonedx", version, errors: valid ? [] : validationErrors(validateCycloneDx16) };
    }
    return { valid: false, format: "cyclonedx", version, errors: [`No official JSON schema is bundled for cyclonedx ${version}`] };
  }

  if (typeof candidate.spdxVersion === "string" && candidate.spdxVersion.startsWith("SPDX-")) {
    const version = candidate.spdxVersion;
    if (version !== "SPDX-2.3") {
      return { valid: false, format: "spdx", version, errors: [`No official JSON schema is bundled for spdx ${version}`] };
    }
    const valid = validateSpdx23(document);
    return { valid: Boolean(valid), format: "spdx", version, errors: valid ? [] : validationErrors(validateSpdx23) };
  }

  return { valid: false, format: "cyclonedx", version: "unknown", errors: ["Document format/version could not be identified"] };
}
