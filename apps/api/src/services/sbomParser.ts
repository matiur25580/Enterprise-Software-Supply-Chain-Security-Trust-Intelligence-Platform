import { createHash } from "node:crypto";

export type SbomFormat = "cyclonedx" | "spdx";
export interface NormalizedComponent {
  name: string;
  version?: string;
  purl?: string;
  supplier?: string;
  componentType?: string;
}
export interface ParsedSbom {
  format: SbomFormat;
  formatVersion: string;
  documentName: string;
  documentVersion?: string;
  componentCount: number;
  documentDigest: string;
  normalizedComponents: NormalizedComponent[];
}
export class SbomValidationError extends Error {
  constructor(message: string) { super(message); this.name = "SbomValidationError"; }
}
const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const cleanText = (value: unknown, field: string, max = 200): string => {
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    throw new SbomValidationError(`Invalid or missing ${field}`);
  }
  return value.trim();
};
const optionalText = (value: unknown, max = 200): string | undefined =>
  typeof value === "string" && value.trim() ? value.trim().slice(0, max) : undefined;

function normalizePurl(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || value.length > 1024 || !value.startsWith("pkg:")) {
    throw new SbomValidationError("Component purl must use the package-url (pkg:) scheme");
  }
  // Reject control characters and whitespace; retain the canonical source string.
  if (/[\u0000-\u0020\u007f]/.test(value)) throw new SbomValidationError("Component purl contains invalid characters");
  return value;
}

function normalizeComponents(raw: unknown[], nameField: string): NormalizedComponent[] {
  if (raw.length > 10000) throw new SbomValidationError("SBOM exceeds the 10,000 component ingestion limit");
  const seen = new Set<string>();
  return raw.map((entry, index) => {
    if (!isObject(entry)) throw new SbomValidationError(`Component at index ${index} must be an object`);
    const name = cleanText(entry[nameField], `component[${index}].${nameField}`, 500);
    const version = optionalText(entry.version ?? entry.versionInfo, 200);
    const externalPurl = Array.isArray(entry.externalRefs) ? entry.externalRefs.find((ref) => isObject(ref) && ref.referenceCategory === "PACKAGE-MANAGER" && ref.referenceType === "purl") : undefined;
    const purl = normalizePurl(entry.purl ?? (isObject(externalPurl) ? externalPurl.referenceLocator : undefined));
    const supplierValue = isObject(entry.supplier) ? entry.supplier.name : entry.supplier;
    const supplier = optionalText(supplierValue, 200);
    const componentType = optionalText(entry.type, 80);
    const identity = purl ?? `${name.toLowerCase()}@${(version ?? "").toLowerCase()}`;
    if (seen.has(identity)) throw new SbomValidationError(`Duplicate component identity: ${identity.slice(0, 120)}`);
    seen.add(identity);
    return { name, ...(version ? { version } : {}), ...(purl ? { purl } : {}), ...(supplier ? { supplier } : {}), ...(componentType ? { componentType } : {}) };
  });
}

export function parseSbomDocument(document: unknown): ParsedSbom {
  if (!isObject(document)) throw new SbomValidationError("SBOM document must be a JSON object");
  let format: SbomFormat;
  let formatVersion: string;
  let documentName: string;
  let documentVersion: string | undefined;
  let components: NormalizedComponent[];

  if (document.bomFormat === "CycloneDX") {
    format = "cyclonedx";
    formatVersion = cleanText(document.specVersion, "CycloneDX specVersion", 40);
    if (!/^1\.(4|5|6)$/.test(formatVersion)) throw new SbomValidationError("Supported CycloneDX spec versions are 1.4, 1.5 and 1.6");
    const metadata = isObject(document.metadata) ? document.metadata : {};
    const metadataComponent = isObject(metadata.component) ? metadata.component : {};
    documentName = optionalText(metadataComponent.name, 200) ?? "unnamed-cyclonedx-bom";
    documentVersion = optionalText(metadataComponent.version, 100);
    if (!Array.isArray(document.components)) throw new SbomValidationError("CycloneDX components must be an array");
    components = normalizeComponents(document.components, "name");
  } else if (typeof document.spdxVersion === "string" && document.spdxVersion.startsWith("SPDX-")) {
    format = "spdx";
    formatVersion = cleanText(document.spdxVersion, "SPDX version", 40);
    if (formatVersion !== "SPDX-2.3") throw new SbomValidationError("Only SPDX-2.3 JSON documents are currently supported");
    documentName = cleanText(document.name, "SPDX document name", 200);
    documentVersion = optionalText(document.documentNamespace, 100);
    if (!Array.isArray(document.packages)) throw new SbomValidationError("SPDX packages must be an array");
    components = normalizeComponents(document.packages, "name");
  } else {
    throw new SbomValidationError("Document is not a supported CycloneDX or SPDX JSON SBOM");
  }

  const serialized = JSON.stringify(document);
  if (Buffer.byteLength(serialized, "utf8") > 2 * 1024 * 1024) {
    throw new SbomValidationError("SBOM document exceeds the 2 MiB ingestion limit");
  }
  const documentDigest = createHash("sha256").update(serialized, "utf8").digest("hex");
  return { format, formatVersion, documentName, ...(documentVersion ? { documentVersion } : {}), componentCount: components.length, documentDigest, normalizedComponents: components };
}
