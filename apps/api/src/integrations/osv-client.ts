import {z} from "zod";
import type {NormalizedSbomComponent} from "./sbom-parser.js";
const OSV_BASE="https://api.osv.dev";
const MAX_PACKAGES=500,MAX_VULNERABILITIES=2000,MAX_FINDINGS=5000,MAX_PAGES=10,BATCH_SIZE=100,DETAIL_CONCURRENCY=6;
const osvStubSchema=z.object({id:z.string().min(1).max(128),modified:z.string().optional()});
const batchResponseSchema=z.object({results:z.array(z.object({vulns:z.array(osvStubSchema).optional(),next_page_token:z.string().optional()}).passthrough())});
const referenceSchema=z.object({type:z.string().optional(),url:z.string().url().optional()}).passthrough();
const affectedSchema=z.object({
 package:z.object({name:z.string().optional(),ecosystem:z.string().optional(),purl:z.string().optional()}).optional(),
 ranges:z.array(z.object({type:z.string().optional(),events:z.array(z.record(z.string(),z.unknown())).optional()}).passthrough()).optional(),
 versions:z.array(z.string()).optional(),ecosystem_specific:z.record(z.string(),z.unknown()).optional(),database_specific:z.record(z.string(),z.unknown()).optional()
}).passthrough();
const vulnerabilitySchema=z.object({
 id:z.string().min(1).max(128),summary:z.string().optional(),details:z.string().optional(),aliases:z.array(z.string()).optional(),
 modified:z.string().optional(),published:z.string().optional(),withdrawn:z.string().optional(),references:z.array(referenceSchema).optional(),
 affected:z.array(affectedSchema).optional(),severity:z.array(z.object({type:z.string().optional(),score:z.string().optional()}).passthrough()).optional(),
 database_specific:z.record(z.string(),z.unknown()).optional()
}).passthrough();
export interface OsvFinding {
 packageUrl:string;vulnerabilityId:string;summary:string;details:string|null;aliases:string[];publishedAt:string|null;modifiedAt:string|null;
 severity:"critical"|"high"|"moderate"|"low"|"unknown";cvssScore:number|null;affectedVersions:string[];fixedVersions:string[];
 references:Array<{type:string;url:string}>;recommendedAction:string;source:"OSV";
}
export interface OsvScanResult {findings:OsvFinding[];scannedPackages:number;skippedPackages:number;vulnerabilityCount:number;}
function cleanText(value:unknown,max=4000):string|null{return typeof value==="string"&&value.trim()?value.trim().slice(0,max):null;}
export function versionedPurl(component:NormalizedSbomComponent):string|null{
 const purl=component.purl?.trim();
 if(!purl||purl.length>1024||!/^pkg:[a-z0-9.+-]+\//i.test(purl))return null;
 const suffixIndex=[purl.indexOf("?"),purl.indexOf("#")].filter(index=>index>=0).reduce((a,b)=>Math.min(a,b),purl.length);
 const base=purl.slice(0,suffixIndex);
 if(/\/[^/]+@[^/]+$/.test(base))return purl;
 if(!component.version)return null;
 return `${base}@${encodeURIComponent(component.version)}${purl.slice(suffixIndex)}`;
}
function cvssV3Score(vector:string):number|null{
 const metrics=Object.fromEntries(vector.split("/").slice(1).map(part=>part.split(":"))) as Record<string,string>;
 const av:Record<string,number>={N:0.85,A:0.62,L:0.55,P:0.2},ac:Record<string,number>={L:0.77,H:0.44},ui:Record<string,number>={N:0.85,R:0.62};
 const impactMetric:Record<string,number>={H:0.56,L:0.22,N:0};
 const scope=metrics.S;
 if(!Object.prototype.hasOwnProperty.call(av,metrics.AV)||!Object.prototype.hasOwnProperty.call(ac,metrics.AC)||!Object.prototype.hasOwnProperty.call(ui,metrics.UI)||!Object.prototype.hasOwnProperty.call(impactMetric,metrics.C)||!Object.prototype.hasOwnProperty.call(impactMetric,metrics.I)||!Object.prototype.hasOwnProperty.call(impactMetric,metrics.A)||(scope!=="U"&&scope!=="C"))return null;
 const prValues=scope==="C"?{N:0.85,L:0.68,H:0.5}:{N:0.85,L:0.62,H:0.27};
 const pr=prValues[metrics.PR as "N"|"L"|"H"];if(pr===undefined)return null;
 const impactSub=1-(1-impactMetric[metrics.C!]!)*(1-impactMetric[metrics.I!]!)*(1-impactMetric[metrics.A!]!);
 const impact=scope==="U"?6.42*impactSub:7.52*(impactSub-0.029)-3.25*Math.pow(impactSub-0.02,15);
 if(impact<=0)return 0;
 const exploitability=8.22*av[metrics.AV!]!*ac[metrics.AC!]!*pr*ui[metrics.UI!]!;
 const base=scope==="U"?Math.min(impact+exploitability,10):Math.min(1.08*(impact+exploitability),10);
 return Math.ceil(base*10-1e-9)/10;
}
function severityFrom(vulnerability:z.infer<typeof vulnerabilitySchema>):{severity:OsvFinding["severity"];score:number|null}{
 const candidates:unknown[]=[];
 for(const entry of vulnerability.severity??[]){if(entry.score){const numeric=Number(entry.score);if(Number.isFinite(numeric)&&numeric>=0&&numeric<=10)candidates.push(numeric);else {const cvss=cvssV3Score(entry.score);if(cvss!==null)candidates.push(cvss);}}}
 for(const affected of vulnerability.affected??[]){const label=affected.ecosystem_specific?.severity;if(typeof label==="string")candidates.push(label);}
 const dbSeverity=vulnerability.database_specific?.severity;if(typeof dbSeverity==="string")candidates.push(dbSeverity);
 const scores=candidates.filter((value):value is number=>typeof value==="number");
 const score=scores.length?Math.max(...scores):null;
 if(score!==null)return {score,severity:score>=9?"critical":score>=7?"high":score>=4?"moderate":"low"};
 for(const candidate of candidates){if(typeof candidate!=="string")continue;const value=candidate.toLowerCase();
  if(value.includes("critical"))return {score:null,severity:"critical"};
  if(value.includes("high"))return {score:null,severity:"high"};
  if(value.includes("moderate")||value.includes("medium"))return {score:null,severity:"moderate"};
  if(value.includes("low"))return {score:null,severity:"low"};
 }
 return {score:null,severity:"unknown"};
}
function extractVersions(vulnerability:z.infer<typeof vulnerabilitySchema>):{affected:string[];fixed:string[]}{
 const affected=new Set<string>(),fixed=new Set<string>();
 for(const item of vulnerability.affected??[]){for(const version of item.versions??[])if(version.length<=256)affected.add(version);
  for(const range of item.ranges??[])for(const event of range.events??[])if(typeof event.fixed==="string"&&event.fixed.length<=256)fixed.add(event.fixed);}
 return {affected:[...affected].slice(0,100),fixed:[...fixed].slice(0,50)};
}
function normalizeVulnerability(vulnerability:z.infer<typeof vulnerabilitySchema>,packageUrl:string):OsvFinding{
 const {severity,score}=severityFrom(vulnerability),versions=extractVersions(vulnerability);
 const references=(vulnerability.references??[]).flatMap(reference=>reference.url?[{type:reference.type??"WEB",url:reference.url}]:[]).slice(0,30);
 const recommendedAction=versions.fixed.length?`Upgrade the affected dependency to ${versions.fixed.slice(0,5).join(", ")} (or a later vendor-confirmed safe release), then regenerate and rescan the SBOM.`:"Review the upstream advisory and vendor guidance, then upgrade to a verified unaffected release. OSV did not provide a fixed version.";
 return {packageUrl,vulnerabilityId:vulnerability.id,summary:cleanText(vulnerability.summary,1000)??vulnerability.id,details:cleanText(vulnerability.details,8000),aliases:(vulnerability.aliases??[]).slice(0,30),publishedAt:cleanText(vulnerability.published,64),modifiedAt:cleanText(vulnerability.modified,64),severity,cvssScore:score,affectedVersions:versions.affected,fixedVersions:versions.fixed,references,recommendedAction,source:"OSV"};
}
async function requestJson(url:string,init?:RequestInit):Promise<unknown>{
 const response=await fetch(url,{...init,signal:AbortSignal.timeout(10_000),headers:{"accept":"application/json","user-agent":"ChainProof/0.1 vulnerability-intelligence",...(init?.headers??{})}});
 if(!response.ok)throw new Error(`OSV request failed with HTTP ${response.status}.`);
 return response.json();
}
async function queryBatch(packages:string[]):Promise<Map<string,Set<string>>>{
 const idsByPackage=new Map(packages.map(purl=>[purl,new Set<string>()]));
 let pending=packages.map(purl=>({purl,pageToken:undefined as string|undefined}));
 let pages=0;
 while(pending.length){
  if(++pages>MAX_PAGES)throw new Error("OSV pagination exceeded the safety limit; scan was not completed.");
  const payload=await requestJson(`${OSV_BASE}/v1/querybatch`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({queries:pending.map(item=>({package:{purl:item.purl},...(item.pageToken?{page_token:item.pageToken}:{})}))})});
  const parsed=batchResponseSchema.safeParse(payload);
  if(!parsed.success||parsed.data.results.length!==pending.length)throw new Error("OSV returned an invalid batch response.");
  const next:Array<{purl:string;pageToken:string}>=[];
  parsed.data.results.forEach((result,index)=>{const purl=pending[index]!.purl;for(const vuln of result.vulns??[])idsByPackage.get(purl)!.add(vuln.id);if(result.next_page_token)next.push({purl,pageToken:result.next_page_token});});
  let total=0;for(const ids of idsByPackage.values())total+=ids.size;
  if(total>MAX_VULNERABILITIES)throw new Error("OSV returned more findings than the scan safety limit.");
  pending=next;
 }
 return idsByPackage;
}
async function fetchDetails(ids:string[]):Promise<Map<string,z.infer<typeof vulnerabilitySchema>>>{
 const output=new Map<string,z.infer<typeof vulnerabilitySchema>>();let cursor=0;
 const workers=Array.from({length:Math.min(DETAIL_CONCURRENCY,ids.length)},async()=>{while(true){const index=cursor++;if(index>=ids.length)return;const id=ids[index]!;
  const payload=await requestJson(`${OSV_BASE}/v1/vulns/${encodeURIComponent(id)}`);const parsed=vulnerabilitySchema.safeParse(payload);
  if(!parsed.success||parsed.data.id!==id)throw new Error(`OSV returned invalid details for advisory ${id}.`);output.set(id,parsed.data);
 }});
 await Promise.all(workers);return output;
}
export async function scanComponentsWithOsv(components:NormalizedSbomComponent[]):Promise<OsvScanResult>{
 const unique=new Map<string,NormalizedSbomComponent>();
 for(const component of components){const purl=versionedPurl(component);if(purl&&!unique.has(purl))unique.set(purl,component);}
 const packages=[...unique.keys()];
 if(packages.length>MAX_PACKAGES)throw new Error(`SBOM has more than ${MAX_PACKAGES} scannable unique packages; split the inventory before scanning.`);
 const idsByPackage=new Map<string,Set<string>>();
 for(let offset=0;offset<packages.length;offset+=BATCH_SIZE){const page=await queryBatch(packages.slice(offset,offset+BATCH_SIZE));for(const [purl,ids] of page)idsByPackage.set(purl,ids);}
 let findingPairs=0;for(const ids of idsByPackage.values())findingPairs+=ids.size;\n if(findingPairs>MAX_FINDINGS)throw new Error("OSV returned more package-advisory matches than the scan safety limit.");\n const allIds=[...new Set([...idsByPackage.values()].flatMap(ids=>[...ids]))];
 if(allIds.length>MAX_VULNERABILITIES)throw new Error("OSV returned more findings than the scan safety limit.");
 const details=await fetchDetails(allIds),findings:OsvFinding[]=[];
 for(const [purl,ids] of idsByPackage)for(const id of ids){const detail=details.get(id);if(detail)findings.push(normalizeVulnerability(detail,purl));}
 return {findings,scannedPackages:packages.length,skippedPackages:components.length-scannableComponents,vulnerabilityCount:findings.length};
}
export const osvLimits={maxPackages:MAX_PACKAGES,maxVulnerabilities:MAX_VULNERABILITIES,maxFindings:MAX_FINDINGS,detailConcurrency:DETAIL_CONCURRENCY};
