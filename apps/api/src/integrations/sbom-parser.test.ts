import test from "node:test";
import assert from "node:assert/strict";
import {parseSbomDocument} from "./sbom-parser.js";
const json=(value:unknown)=>Buffer.from(JSON.stringify(value));
test("parses CycloneDX and normalizes nested components and package metadata",()=>{
 const result=parseSbomDocument(json({bomFormat:"CycloneDX",specVersion:"1.6",serialNumber:"urn:uuid:abc",metadata:{component:{name:"payments-api"}},components:[{type:"library",name:"express",version:"5.1.0",purl:"pkg:npm/express@5.1.0",licenses:[{license:{id:"MIT"}}],components:[{name:"accepts",version:"2.0.0"}]}]}));
 assert.equal(result.format,"cyclonedx");assert.equal(result.componentCount,2);assert.equal(result.components[0]?.purl,"pkg:npm/express@5.1.0");assert.deepEqual(result.components[0]?.licenses,["MIT"]);assert.equal(result.documentName,"payments-api");
});
test("parses SPDX package data and extracts package URLs",()=>{
 const result=parseSbomDocument(json({spdxVersion:"SPDX-2.3",SPDXID:"SPDXRef-DOCUMENT",name:"demo",packages:[{SPDXID:"SPDXRef-Package",name:"lodash",versionInfo:"4.17.21",licenseDeclared:"MIT",externalRefs:[{referenceCategory:"PACKAGE-MANAGER",referenceType:"purl",referenceLocator:"pkg:npm/lodash@4.17.21"}]}]}));
 assert.equal(result.format,"spdx");assert.equal(result.componentCount,1);assert.equal(result.components[0]?.purl,"pkg:npm/lodash@4.17.21");assert.deepEqual(result.components[0]?.licenses,["MIT"]);
});
test("rejects malformed, unsupported, nameless and oversized SBOMs",()=>{
 assert.throws(()=>parseSbomDocument(Buffer.from("{")));
 assert.throws(()=>parseSbomDocument(json({format:"unknown"})));
 assert.throws(()=>parseSbomDocument(json({bomFormat:"CycloneDX",specVersion:"1.6",components:[{}]})));
 assert.throws(()=>parseSbomDocument(json({bomFormat:"CycloneDX",specVersion:"1.6",components:Array.from({length:5001},(_,i)=>({name:"pkg-"+i}))})));
});
test("rejects excessive nested component depth",()=>{
 let component:Record<string,unknown>={name:"deep"};
 for(let i=0;i<34;i++)component={name:"nested",components:[component]};
 assert.throws(()=>parseSbomDocument(json({bomFormat:"CycloneDX",specVersion:"1.6",components:[component]})),/depth/);
});
