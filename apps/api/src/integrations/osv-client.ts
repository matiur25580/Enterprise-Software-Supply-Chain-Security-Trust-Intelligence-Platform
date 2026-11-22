import {z} from "zod";
import type {NormalizedSbomComponent} from "./sbom-parser.js";
const OSV_BASE="https://api.osv.dev";
const MAX_PACKAGES=500;
const MAX_VULNERABILITIES=2000;
const MAX_PAGES=10;
const BATCH_SIZE=100;
const DETAIL_CONCURRENCY=6;
const timeoutMs=10_000;
const osvStubSchema=z.object({id:z.string().min(1).max(128),modified:z.string().optional()});
const batchResponseSchema=z.object({results:z.array(z.object({vulns:z.array(osvStubSchema).optional(),next_page_token:z.string().optional()}).passthrough())});
const referenceSchema=z.object({type:z.string().optional(),url:z.string().url().optional()}).passthrough();
const affectedSchema=z.object({
 package:z.object({name:z.string().optional(),ecosystem:z.string().optional(),purl:z.string().optional()}).optional(),
 ranges:z.array(z.object({type:z.string().optional(),events:z.array(z.record(z.string(),z.unknown())).optional()}).passthrough()).optional(),
 versions:z.array(z.string()).optional(),
 ecosystem_specific:z.record(z.string(),z.unknown()).optional(),
 database_specific:z.record(z.string(),z.unknown()).optional()
}).passthrough();
const vulnerabilitySchema=z.object({
 id:z.string().min(1).max(128),summary:z.string().optional(),details:z.string().optional(),
 aliases:z.array(z.string()).optional(),modified:z.string().optional(),published:z.string().optional,
 withdrawn:z.string().optional(),references:z.array(referenceSchema).optional(),
 affected:z.array(affectedSchema).optional(),severity:z.array(z.object({type:z.string().optional(),score:z.string().optional()}).passthrough()).optional(),
 database_specific:z.record(z.string(),z.unknown()).optional()
}).passthrough();
export interface OsvFinding {
 vulnerabilityId:string;summary:string;details:string|null;aliases:string[];publishedAt:string|null;modifiedAt:string|null;
 severity:"critical"|"high"|"moderate"|"low"|"unknown";cvssScore:number|null;
 affectedVersions:string[];fixedVersions:string[];references:Array<{type:string;url:string}>;
 recommendedAction:string;source:"OSV";
}
export interface OsvScanResult {findings:OsvFinding[];scannedPackages:number;skippedPackages:number;vulnerabilityCount:number;}
function cleanText(value:unknown,max=4000):string|null{return typeof value==="string"&&value.trim()?value.trim().slice(0,max):null;}
function versionedPurl(component:NormalizedSbomComponent):string|null{
 const purl=component.purl?.trim();
 if(!purl||purl.length>1024||!/^pkg:[a-z0-9.+-]+\//i.test(purl))return null;
 const suffixIndex=[purl.indexOf("?"),purl.indexOf("#")].filter(index=>index>=0).reduce((a,b)=>Math.min(a,b),purl.length);
 const base=purl.slice(0,suffixIndex);
 const hasVersion=/\/[^/]+@[^/]+$/.test(base);
 if(hasVersion)return purl;
 if(!component.version)return null;
 const suffix=purl.slice(suffixIndex);
 return `${base}@${encodeURIComponent(component.version)}${suffix}`;
}
function severityFrom(vulnerability:z.infer<typeof vulnerabilitySchema>):{severity:OsvFinding["severity"];score:number|null}{
 const candidates:unknown[]=[];
 for(const entry of vulnerability.severity??[]){
  if(entry.score){const numeric=Number(entry.score);if(Number.isFinite(numeric)&&numeric>=0&&numeric<=10)candidates.push(numeric);}
 }
 for(const affected of vulnerability.affected??[]){
  const label=affected.ecosystem_specific?.severity;
  if(typeof label==="string")candidates.push(label);
 }
 const dbSeverity=vulnerability.database_specific?.severity;
 if(typeof dbSeverity==="string")candidates.push(dbSeverity);
 const scores=candidates.filter((value):value is number=>typeof value==="number");
 const score=scores.length?Math.max(...scores):null;
 if(score!==null)return {score,severity:score>=9?"critical":score>=7?"high":score>=4?"moderate":"low"};
 for(const candidate of candidates){
  if(typeof candidate!=="string")continue;
  const normalized=candidate.toLowerCase();
  if(normalized.includes("critical"))return {score:null,severity:"critical"};
  if(normalized.includes("high"))return {score:null,severity:"high"};
  if(normalized.includes("moderate")||normalized.includes("medium"))return {score:null,severity:"moderate"};
  if(normalized.includes("low"))return {score:null,severity:"low"};
 }
 return {score:null,severity:"unknown"};
}
function extractVersions(vulnerability:z.infer<typeof vulnerabilitySchema>):{affected:string[];fixed:string[]}{
 const affected=new Set<string>(),fixed=new Set<string>();
 for(const item of vulnerability.affected??[]){
  for(const version of item.versions??[])if(version.length<=256)affected.add(version);
  for(const range of item.ranges??[])for(const event of range.events??[]){
   if(typeof event.fixed==="string"&&event.fixed.length<=256)fixed.add(event.fixed);
  }
 }
 return {affected:[...affected].slice(0,100),fixed:[...fixed].slice(0,50)};
}
function normalizeVulnerability(vulnerability:z.infer<typeof vulnerabilitySchema>):OsvFinding{
 const {severity,score}=severityFrom(vulnerability),versions=extractVersions(vulnerability);
 const references=(vulnerability.references??[]).flatMap(reference=>reference.url?[{type:reference.type??"WEB",url:reference.url}]:[]).slice(0,30);
 const recommendedAction=versions.fixed.length? `Upgrade the affected dependency to ${versions.fixed.slice(0,5).join(", ")} (or a later vendor-confirmed safe release), then regenerate and rescan the SBOM.`:"Review the upstream advisory and vendor guidance, then upgrade to a verified unaffected release. No fixed version was supplied by OSV.";
 return {vulnerabilityId:vulnerability.id,summary:cleanText(vulnerability.summary,1000)??vulnerability.id,details:cleanText(vulnerability.details,8000),aliases:(vulnerability.aliases??[]).slice(0,30),publishedAt:cleanText(vulnerability.published,64),modifiedAt:cleanText(vulnerability.modified,64),severity,cvssScore:score,affectedVersions:versions.affected,fixedVersions:versions.fixed,references,recommendedAction,source:"OSV"};
}
async function requestJson(url:string,init?:RequestInit):Promise<unknown>{
 const response=await fetch(url,{...init,signal:AbortSignal.timeout(timeoutMs),headers:{"accept":"application/json","user-agent":"ChainProof/0.1 vulnerability-intelligence",...(init?.headers??{})}});
 if(!response.ok)throw new Error(`OSV request failed with HTTP ${response.status}.`);
 return response.json();
}
async function queryBatch(queries:Array<{package:{purl:string}}>):Promise<string[]>{
 const ids=new Set<string>();
 let pending=queries.map(query=>({query,pageToken:undefined as string|undefined}));
 let pages=0;
 while(pending.length){
  if(++pages>MAX_PAGES)throw new Error("OSV pagination exceeded the safety limit; scan was not completed.");
  const payload=await requestJson(`${OSV_BASE}/v1/querybatch`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({queries:pending.map(item=>({...item.query,...(item.pageToken?{page_token:item.pageToken}:{})}))})});
  const parsed=batchResponseSchema.safeParse(payload);
  if(!parsed.success||parsed.data.results.length!==pending.length)throw new Error("OSV returned an invalid batch response.");
  const next:Array<{query:{package:{purl:string}};pageToken:string}>=[];
  parsed.data.results.forEach((result,index)=>{
   for(const vulnerability of result.vulns??[])ids.add(vulnerability.id);
   if(result.next_page_token)next.push({query:pending[index]!.query,pageToken:result.next_page_token});
  });
  if(ids.size>MAX_VULNERABILITIES)throw new Error("OSV returned more findings than the scan safety limit.");
  pending=next;
 }
 return [...ids];
}
async function fetchDetails(ids:string[]):Promise<OsvFinding[]>{
 const output:OsvFinding[]=[];
 let cursor=0;
 const workers=Array.from({length:Math.min(DETAIL_CONCURRENCY,ids.length)},async()=>{
  while(true){
   const index=cursor++;
   if(index>=ids.length)return;
   const id=ids[index]!;
   const payload=await requestJson(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`);
   const parsed=vulnerabilitySchema.safeParse(payload);
   if(!parsed.success||parsed.data.id!==id)throw new Error(`OSV returned invalid details for advisory ${id}.`);
   output[index]=normalizeVulnerability(parsed.data);
  }
 });
 await Promise.all(workers);
 return output;
}
export async function scanComponentsWithOsv(components:NormalizedSbomComponent[]):Promise<OsvScanResult>{
 const unique=new Map<string,NormalizedSbomComponent>();
 for(const component of components){const purl=versionedPurl(component);if(purl&&!unique.has(purl))unique.set(purl,component);}
 const packages=[...unique.keys()];
 if(packages.length>MAX_PACKAGES)throw new Error(`SBOM has more than ${MAX_PACKAGES} scannable unique packages; split the inventory before scanning.`);
 const ids:string[]=[];
 for(let offset=0;offset<packages.length;offset+=BATCH_SIZE){
  ids.push(...await queryBatch(packages.slice(offset,offset+BATCH_SIZE).map(purl=>({package:{purl}}))));
  if(ids.length>MAX_VULNERABILITIES)throw new Error("OSV returned more findings than the scan safety limit.");
 }
 const findings=await fetchDetails([...new Set(ids)]);
 return {findings,scannedPackages:packages.length,skippedPackages:components.length-packages.length,vulnerabilityCount:findings.length};
}
export const osvLimits={maxPackages:MAX_PACKAGES,maxVulnerabilities:MAX_VULNERABILITIES,detailConcurrency:DETAIL_CONCURRENCY};
