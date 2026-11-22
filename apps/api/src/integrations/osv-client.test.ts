import test from "node:test";
import assert from "node:assert/strict";
import {scanComponentsWithOsv} from "./osv-client.js";
import type {NormalizedSbomComponent} from "./sbom-parser.js";
const component=(name:string,version:string,purl:string|null):NormalizedSbomComponent=>({bomRef:null,name,group:null,version,purl,cpe:null,licenses:[]});
test("queries versioned package URLs, fetches full advisory details, and derives safe remediation",async()=>{
 const original=globalThis.fetch;
 const calls:Array<{url:string;body?:string}>=[];
 globalThis.fetch=async(input,init)=>{
  const url=String(input);calls.push({url,body:typeof init?.body==="string"?init.body:undefined});
  if(url.endsWith("/v1/querybatch"))return new Response(JSON.stringify({results:[{vulns:[{id:"GHSA-test-1234"}]},{vulns:[{id:"GHSA-test-1234"}]}]}),{status:200,headers:{"content-type":"application/json"}});
  if(url.endsWith("/v1/vulns/GHSA-test-1234"))return new Response(JSON.stringify({id:"GHSA-test-1234",summary:"Example advisory",severity:[{type:"CVSS_V3",score:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],affected:[{versions:["1.0.0"],ranges:[{events:[{introduced:"0"},{fixed:"1.0.1"}]}]}],references:[{type:"ADVISORY",url:"https://example.test/advisory"}]}),{status:200,headers:{"content-type":"application/json"}});
  return new Response("not found",{status:404});
 };
 try{
  const result=await scanComponentsWithOsv([component("demo","1.0.0","pkg:npm/demo"),component("demo","1.0.0","pkg:npm/demo"),component("other","2.0.0","pkg:npm/other"),component("unknown","1.0.0",null)]);
  assert.equal(result.scannedPackages,2);assert.equal(result.skippedPackages,1);assert.equal(result.vulnerabilityCount,2);
  assert.equal(result.findings[0]?.severity,"critical");assert.equal(result.findings[0]?.cvssScore,9.8);
  assert.deepEqual(result.findings[0]?.fixedVersions,["1.0.1"]);
  assert.match(result.findings[0]?.recommendedAction??"",/1.0.1/);
  assert.match(calls[0]?.body??"",/pkg:npm\/demo@1.0.0/);
  assert.equal(calls.length,2);
 }finally{globalThis.fetch=original;}
});
test("handles clean packages and rejects malformed OSV responses",async()=>{
 const original=globalThis.fetch;
 globalThis.fetch=async()=>new Response(JSON.stringify({results:[{}]}),{status:200,headers:{"content-type":"application/json"}});
 try{
  const clean=await scanComponentsWithOsv([component("no-purl","1.0",null)]);
  assert.equal(clean.scannedPackages,0);assert.equal(clean.skippedPackages,1);
  await assert.rejects(()=>scanComponentsWithOsv([component("demo","1.0","pkg:npm/demo")]),/invalid batch response/);
 }finally{globalThis.fetch=original;}
});
test("rejects non-success OSV responses rather than reporting a clean scan",async()=>{
 const original=globalThis.fetch;globalThis.fetch=async()=>new Response("unavailable",{status:503});
 try{await assert.rejects(()=>scanComponentsWithOsv([component("demo","1.0","pkg:npm/demo")]),/HTTP 503/);}
 finally{globalThis.fetch=original;}
});
