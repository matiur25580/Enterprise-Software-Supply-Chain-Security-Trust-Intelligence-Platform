import { afterEach, describe, expect, it, vi } from "vitest";
import { OsvServiceError, queryOsvByPurls } from "../src/services/osvClient";

afterEach(() => vi.unstubAllGlobals());

describe("OSV batch client", () => {
  it("deduplicates PURLs and maps advisory identifiers and safe references", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      results: [{ vulns: [{
        id: "GHSA-abcd", summary: "Example advisory", aliases: ["CVE-2026-1234"],
        references: [{ type: "WEB", url: "https://osv.dev/vulnerability/GHSA-abcd" }, { type: "WEB", url: "javascript:alert(1)" }]
      }] }]
    }), { status: 200, headers: { "content-type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await queryOsvByPurls(["pkg:npm/express@4.21.2", "pkg:npm/express@4.21.2"]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ queries: [{ package: { purl: "pkg:npm/express@4.21.2" } }] });
    expect(result[0].vulnerabilities[0]).toMatchObject({ id: "GHSA-abcd", aliases: ["CVE-2026-1234"] });
    expect(result[0].vulnerabilities[0].references).toEqual(["https://osv.dev/vulnerability/GHSA-abcd"]);
  });

  it("rejects invalid package URLs without making a network request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(queryOsvByPurls(["https://example.invalid/package"])).rejects.toBeInstanceOf(OsvServiceError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("enforces the 100-package batch ceiling", async () => {
    await expect(queryOsvByPurls(Array.from({ length: 101 }, (_, i) => `pkg:npm/example-${i}@1.0.0`))).rejects.toThrow(/100/);
  });

  it("fails closed on upstream HTTP errors", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 503 })));
    await expect(queryOsvByPurls(["pkg:npm/example@1.0.0"])).rejects.toThrow(/HTTP 503/);
  });
});
