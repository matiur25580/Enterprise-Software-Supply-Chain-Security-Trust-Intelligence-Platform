export interface OsvVulnerability {
  id: string;
  summary?: string;
  modified?: string;
  published?: string;
  aliases: string[];
  references: string[];
  cvssScore?: number;
  cvssVector?: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
}
export interface OsvPackageResult {
  purl: string;
  vulnerabilities: OsvVulnerability[];
}
export class OsvServiceError extends Error {
  constructor(message: string) { super(message); this.name = "OsvServiceError"; }
}
const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const MAX_PACKAGES_PER_REQUEST = 100;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Query OSV by Package URL. No package names or document contents are sent. */
export async function queryOsvByPurls(purls: string[]): Promise<OsvPackageResult[]> {
  const uniquePurls = [...new Set(purls)];
  if (uniquePurls.length === 0) return [];
  if (uniquePurls.length > MAX_PACKAGES_PER_REQUEST) {
    throw new OsvServiceError("A vulnerability scan is limited to 100 unique package URLs");
  }
  for (const purl of uniquePurls) {
    if (typeof purl !== "string" || !purl.startsWith("pkg:") || purl.length > 1024 || /[\u0000-\u0020\u007f]/.test(purl)) {
      throw new OsvServiceError("Invalid package URL supplied for vulnerability lookup");
    }
  }

  let response: Response;
  try {
    response = await fetch(OSV_QUERY_BATCH_URL, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ queries: uniquePurls.map((purl) => ({ package: { purl } })) }),
      signal: AbortSignal.timeout(12_000)
    });
  } catch {
    throw new OsvServiceError("OSV vulnerability service is unavailable or timed out");
  }
  if (!response.ok) throw new OsvServiceError(`OSV vulnerability service returned HTTP ${response.status}`);
  let payload: unknown;
  try { payload = await response.json(); } catch {
    throw new OsvServiceError("OSV returned an invalid JSON response");
  }
  const batchResults = isRecord(payload) ? payload.results : undefined;
  if (!Array.isArray(batchResults) || batchResults.length !== uniquePurls.length) {
    throw new OsvServiceError("OSV returned an unexpected batch response");
  }

  return uniquePurls.map((purl, index) => {
    const result: unknown = batchResults[index];
    const rawVulnerabilities = isRecord(result) && Array.isArray(result.vulns) ? result.vulns : [];
    const vulnerabilities = rawVulnerabilities.flatMap((raw): OsvVulnerability[] => {
      if (!isRecord(raw) || typeof raw.id !== "string" || raw.id.length > 120) return [];
      const refs = Array.isArray(raw.references) ? raw.references.flatMap((ref) =>
        isRecord(ref) && typeof ref.url === "string" && /^https:\/\//.test(ref.url) ? [ref.url.slice(0, 2048)] : []
      ).slice(0, 20) : [];
      const severityEntries = Array.isArray(raw.severity) ? raw.severity : [];
      const cvssEntry = severityEntries.find((entry) => isRecord(entry) && typeof entry.score === "string" && entry.score.startsWith("CVSS:"));
      const numericScore = isRecord(raw.database_specific) && typeof raw.database_specific.cvss === "number"
        ? raw.database_specific.cvss
        : severityEntries.find((entry) => isRecord(entry) && typeof entry.score === "number")?.score;
      const cvssScore = typeof numericScore === "number" && numericScore >= 0 && numericScore <= 10 ? numericScore : undefined;
      const rawSeverity = isRecord(raw.database_specific) && typeof raw.database_specific.severity === "string"
        ? raw.database_specific.severity.toLowerCase() : "";
      const severity = ["critical", "high", "medium", "low"].includes(rawSeverity)
        ? rawSeverity as "critical" | "high" | "medium" | "low"
        : cvssScore !== undefined
          ? cvssScore >= 9 ? "critical" : cvssScore >= 7 ? "high" : cvssScore >= 4 ? "medium" : cvssScore > 0 ? "low" : "unknown"
          : "unknown";
      return [{
        id: raw.id,
        ...(cvssScore !== undefined ? { cvssScore } : {}),
        ...(isRecord(cvssEntry) && typeof cvssEntry.score === "string" ? { cvssVector: cvssEntry.score.slice(0, 500) } : {}),
        severity,
        ...(typeof raw.summary === "string" ? { summary: raw.summary.slice(0, 1000) } : {}),
        ...(typeof raw.modified === "string" ? { modified: raw.modified } : {}),
        ...(typeof raw.published === "string" ? { published: raw.published } : {}),
        aliases: Array.isArray(raw.aliases) ? raw.aliases.filter((alias): alias is string => typeof alias === "string").slice(0, 20) : [],
        references: refs
      }];
    });
    return { purl, vulnerabilities };
  });
}
