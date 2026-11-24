import { describe, expect, it } from "vitest";
import { findActiveVexAcceptance } from "../src/services/vexRiskAcceptance";

const now = new Date("2026-11-24T12:00:00.000Z");
const acceptance = {
  exceptionId: "exception-1", advisoryId: "GHSA-1", purl: "pkg:npm/example@1.0.0",
  rationale: "The affected code path is unreachable in this deployment.",
  compensatingControls: "Runtime policy and request validation are enabled.",
  acceptedBy: "security-reviewer", acceptedAt: "2026-11-20T12:00:00.000Z",
  expiresAt: "2026-12-20T12:00:00.000Z", status: "accepted" as const
};

describe("VEX risk acceptance matching", () => {
  it("matches only an active exception for the exact advisory and package URL", () => {
    expect(findActiveVexAcceptance({ id: "GHSA-1", purl: "pkg:npm/example@1.0.0" }, [acceptance], now)).toEqual(acceptance);
    expect(findActiveVexAcceptance({ id: "GHSA-1", purl: "pkg:npm/example@2.0.0" }, [acceptance], now)).toBeUndefined();
    expect(findActiveVexAcceptance({ id: "GHSA-2", purl: "pkg:npm/example@1.0.0" }, [acceptance], now)).toBeUndefined();
  });
  it("ignores expired and revoked acceptances", () => {
    expect(findActiveVexAcceptance({ id: "GHSA-1", purl: acceptance.purl }, [{ ...acceptance, expiresAt: "2026-11-24T11:59:59.000Z" }], now)).toBeUndefined();
    expect(findActiveVexAcceptance({ id: "GHSA-1", purl: acceptance.purl }, [{ ...acceptance, status: "revoked" }], now)).toBeUndefined();
  });
});
