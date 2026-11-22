import {createHash} from "node:crypto";
import {z} from "zod";
export type SbomFormat="cyclonedx"|"spdx";
export interface NormalizedSbomComponent{
 bomRef:string|null;name:string;group:string|null;version:string|null;purl:string|null;cpe:string|null;licenses:string[];
}
export interface ParsedSbom{
 format:SbomFormat;specVersion:string;serialNumber:string|null;documentName:string|null;
 documentSha256:string;componentCount:number;components:NormalizedSbomComponent[];
}
const MAX_COMPONENTS=5000;
const MAX_DEPTH=32;
const text=(value:unknown,max=1024):string|null=>typeof value==="string"&&value.trim().length>0?value.trim().slice(0,max):null;
function componentLicenseValues(value:unknown):string[]{
 if(!Array.isArray(value))return [];
 const values:string[]=[];
 for(const item of value){
  if(!item||typeof item!=="object"||Array.isArray(item))continue;
  const record=item as Record<string,unknown>;
  const license=record.license&&typeof record.license==="object"?record.license as Record<string,unknown>:null;
  const candidate=text(license?.id,128)??text(license?.name,256)??text(record.expression,256);
  if(candidate&&!values.includes(candidate))values.push(candidate);
 }
 return values.slice(0,20);
}
function normalizeCycloneDx(root:Record<string,unknown>,documentSha256:string):ParsedSbom{
 const specVersion=text(root.specVersion,32);
 if(root.bomFormat!=="CycloneDX"||!specVersion||!/^1\.[0-9]+$/.test(specVersion))throw new Error("Unsupported or invalid CycloneDX BOM format/version.");
 const components:NormalizedSbomComponent[]=[];
 const pending:Array<{value:unknown;depth:number}>=(Array.isArray(root.components)?root.components:[]).map(value=>({value,depth:0}));
 while(pending.length){
  const current=pending.pop()!;
  if(current.depth>MAX_DEPTH)throw new Error("SBOM component nesting exceeds the supported depth.");
  if(!current.value||typeof current.value!=="object"||Array.isArray(current.value))throw new Error("SBOM contains an invalid component entry.");
  const item=current.value as Record<string,unknown>;
  const name=text(item.name,256);
  if(!name)throw new Error("Every CycloneDX component must have a name.");
  components.push({bomRef:text(item["bom-ref"],512),name,group:text(item.group,256),version:text(item.version,256),purl:text(item.purl,1024),cpe:text(item.cpe,512),licenses:componentLicenseValues(item.licenses)});
  if(components.length>MAX_COMPONENTS)throw new Error(`SBOM exceeds the ${MAX_COMPONENTS} component limit.`);
  if(item.components!==undefined){
   if(!Array.isArray(item.components))throw new Error("Nested CycloneDX components must be an array.");
   for(const child of item.components)pending.push({value:child,depth:current.depth+1});
  }
 }
 const metadata=root.metadata&&typeof root.metadata==="object"?root.metadata as Record<string,unknown>:{};
 const metadataComponent=metadata.component&&typeof metadata.component==="object"?metadata.component as Record<string,unknown>:{};
 return {format:"cyclonedx",specVersion,serialNumber:text(root.serialNumber,256),documentName:text(metadataComponent.name,256),documentSha256,componentCount:components.length,components};
}
function normalizeSpdx(root:Record<string,unknown>,documentSha256:string):ParsedSbom{
 const specVersion=text(root.spdxVersion,32);
 if(!specVersion||!/^SPDX-2\.[0-9]+$/.test(specVersion))throw new Error("Unsupported or invalid SPDX document version.");
 if(!Array.isArray(root.packages))throw new Error("SPDX document must contain a packages array.");
 if(root.packages.length>MAX_COMPONENTS)throw new Error(`SBOM exceeds the ${MAX_COMPONENTS} component limit.`);
 const components:NormalizedSbomComponent[]=root.packages.map(value=>{
  if(!value||typeof value!=="object"||Array.isArray(value))throw new Error("SPDX contains an invalid package entry.");
  const item=value as Record<string,unknown>;
  const name=text(item.name,256);
  if(!name)throw new Error("Every SPDX package must have a name.");
  const externalRefs=Array.isArray(item.externalRefs)?item.externalRefs:[];
  const purlRef=externalRefs.find(ref=>ref&&typeof ref==="object"&&(ref as Record<string,unknown>).referenceType==="purl") as Record<string,unknown>|undefined;
  const licenses=[text(item.licenseDeclared,256),text(item.licenseConcluded,256)].filter((license):license is string=>Boolean(license));
  return {bomRef:text(item.SPDXID,512),name,group:null,version:text(item.versionInfo,256),purl:text(purlRef?.referenceLocator,1024),cpe:null,licenses:[...new Set(licenses)]};
 });
 return {format:"spdx",specVersion,serialNumber:text(root.SPDXID,256),documentName:text(root.name,256),documentSha256,componentCount:components.length,components};
}
export function parseSbomDocument(raw:Buffer):ParsedSbom{
 if(raw.length===0)throw new Error("SBOM document is empty.");
 const documentSha256=createHash("sha256").update(raw).digest("hex");
 let parsed:unknown;
 try{parsed=JSON.parse(raw.toString("utf8"));}catch{throw new Error("SBOM must be valid JSON.");}
 const rootResult=z.record(z.string(),z.unknown()).safeParse(parsed);
 if(!rootResult.success)throw new Error("SBOM document must be a JSON object.");
 const root=rootResult.data;
 if(root.bomFormat==="CycloneDX")return normalizeCycloneDx(root,documentSha256);
 if(typeof root.spdxVersion==="string")return normalizeSpdx(root,documentSha256);
 throw new Error("Unsupported SBOM format. Upload CycloneDX JSON or SPDX JSON.");
}
export const sbomUploadMetadataSchema=z.object({source:z.enum(["manual","github"]).default("manual"),sourceReference:z.string().trim().min(1).max(512).optional()}).strict();
