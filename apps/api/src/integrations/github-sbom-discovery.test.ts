import test from "node:test";
import assert from "node:assert/strict";
import {boundedSbomCandidatePaths,isSupportedSbomCandidate} from "./github-sbom-discovery.js";
test("recognizes explicit CycloneDX and SPDX SBOM filenames without matching arbitrary JSON",()=>{
 assert.equal(isSupportedSbomCandidate("artifacts/release.cdx.json"),true);
 assert.equal(isSupportedSbomCandidate("security/bom.spdx.json"),true);
 assert.equal(isSupportedSbomCandidate("sbom.json"),true);
 assert.equal(isSupportedSbomCandidate("package.json"),false);
 assert.equal(isSupportedSbomCandidate("src/config.json"),false);
});
test("returns only bounded blob candidates",()=>{
 const paths=boundedSbomCandidatePaths([{path:"sbom.json",type:"blob"},{path:"package.json",type:"blob"},{path:"docs/bom.cdx.json",type:"blob"},{path:"tree",type:"tree"}],false);
 assert.deepEqual(paths,["sbom.json","docs/bom.cdx.json"]);
});
test("fails closed on truncated, huge, or ambiguous repository trees",()=>{
 assert.throws(()=>boundedSbomCandidatePaths([{path:"sbom.json",type:"blob"}],true),/truncated/);
 assert.throws(()=>boundedSbomCandidatePaths(Array.from({length:10001},(_,i)=>({path:String(i),type:"blob"})),false),/10,000/);
 assert.throws(()=>boundedSbomCandidatePaths(Array.from({length:11},(_,i)=>({path:`sbom-${i}.sbom.json`,type:"blob"})),false),/10 candidate/);
});
