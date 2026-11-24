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

const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: true });
addFormats(ajv);
ajv.addSchema(cyclonedxSpdx as AnySchema);
ajv.addSchema(cyclonedxJsf as AnySchema);

const cyclonedxValidators = new Map<string, ValidateFunction>([
  ["1.4", ajv.compile(cyclonedx14 as AnySchema)],
  ["1.5", ajv.compile(cyclonedx15 as AnySchema)],
  ["1.6", ajv.compile(cyclonedx16 as AnySchema)]
]);
const spdxValidator = ajv.compile(spdx23 as AnySchema);

export function validateSbomDocumentSchema(document: unknown): SbomSchemaValidationResult {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return { valid: false, format: "cyclonedx", version: "unknown", errors: ["SBOM document must be a JSON object"] };
  }
  const candidate = document as Record<string, unknown>;
  let format: SbomSchemaFormat;
  let version: string;
  let validator: ValidateFunction | undefined;

  if (candidate.bomFormat === "CycloneDX" && typeof candidate.specVersion === "string") {
    format = "cyclonedx";
    version = candidate.specVersion;
    validator = cyclonedxValidators.get(version);
  } else if (typeof candidate.spdxVersion === "string" && candidate.spdxVersion.startsWith("SPDX-")) {
    format = "spdx";
    version = candidate.spdxVersion;
    validator = version === "SPDX-2.3" ? spdxValidator : undefined;
  } else {
    return { valid: false, format: "cyclonedx", version: "unknown", errors: ["Document format/version could not be identified"] };
  }

  if (!validator) {
    return { valid: false, format, version, errors: [`No official JSON schema is bundled for ${format} ${version}`] };
  }
  const valid = validator(document);
  const errors = valid ? [] : (validator.errors ?? []).slice(0, 12).map((error) =>
    `${error.instancePath || "/"} ${error.message ?? "does not match the official schema"}`
  );
  return { valid: Boolean(valid), format, version, errors };
}
