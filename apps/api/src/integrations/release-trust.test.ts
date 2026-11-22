import assert from "node:assert/strict";
import test from "node:test";
import { assessReleaseTrust } from "./release-trust.js";

const provenance = {
  sourceRepository: "https://github.com/acme/service",
  sourceCommitSha: "a".repeat(40),
  builderIdentity: "github-actions/acme/service",
  buildRunUrl: "https://github.com/acme/service/actions/runs/42"
};
const clean = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };

test("release assessment is explainable and never claims unverified provenance is verified", () => {
  const result = assessReleaseTrust(provenance, clean, "verified");
  assert.equal(result.policyStatus, "eligible");
  assert.equal(result.trustScore, 80);
  assert.ok(result.trustFactors.some(factor => factor.key === "attestation_unverified"));
});

test("critical and high findings block a release with explicit reasons", () => {
  const result = assessReleaseTrust(provenance, { ...clean, critical: 1, high: 2 }, "verified");
  assert.equal(result.policyStatus, "blocked");
  assert.equal(result.trustScore, 0);
  assert.equal(result.policyReasons.length, 2);
});

test("incomplete provenance blocks release eligibility", () => {
  const result = assessReleaseTrust({ ...provenance, sourceCommitSha: "invalid" }, clean, "verified");
  assert.equal(result.policyStatus, "blocked");
  assert.ok(result.policyReasons.some(reason => reason.includes("incomplete")));
});

test("moderate and low findings reduce score without independently blocking", () => {
  const result = assessReleaseTrust(provenance, { ...clean, moderate: 2, low: 1 }, "verified");
  assert.equal(result.policyStatus, "eligible");
  assert.equal(result.trustScore, 73);
});

test("unverified or missing attestation blocks release eligibility", () => {
  const result = assessReleaseTrust(provenance, clean, "not_provided");
  assert.equal(result.policyStatus, "blocked");
  assert.ok(result.policyReasons.some(reason => reason.includes("cryptographic provenance attestation")));
});
