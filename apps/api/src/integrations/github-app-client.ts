import {boundedSbomCandidatePaths} from "./github-sbom-discovery.js";
import {createSign} from "node:crypto";
import {env} from "../config/env.js";
import {z} from "zod";
const API_BASE="https://api.github.com";
const API_VERSION="2022-11-28";
export class GitHubAppError extends Error {
 constructor(public readonly status:number,message:string){super(message);this.name="GitHubAppError";}
}
function base64url(value:string|Buffer):string{return Buffer.from(value).toString("base64url");}
export function createGitHubAppJwt(input:{appId:string;privateKey:string;now?:number}):string {
 const now=input.now??Math.floor(Date.now()/1000);
 const header=base64url(JSON.stringify({alg:"RS256",typ:"JWT"}));
 const payload=base64url(JSON.stringify({iat:now-60,exp:now+540,iss:input.appId}));
 const signingInput=header+"."+payload;
 const signer=createSign("RSA-SHA256");signer.update(signingInput);signer.end();
 return signingInput+"."+signer.sign(input.privateKey).toString("base64url");
}
function configuration(){
 if(!env.GITHUB_APP_ID||!env.GITHUB_APP_PRIVATE_KEY)throw new GitHubAppError(503,"GitHub App credentials are not configured.");
 return {appId:env.GITHUB_APP_ID,privateKey:env.GITHUB_APP_PRIVATE_KEY};
}
async function githubRequest<T>(path:string,token:string,init?:RequestInit):Promise<T>{
 const response=await fetch(API_BASE+path,{
  ...init,
  headers:{
   Accept:"application/vnd.github+json",
   "User-Agent":"ChainProof-Enterprise-App",
   Authorization:"Bearer "+token,
   "X-GitHub-Api-Version":API_VERSION,
   ...(init?.body?{"Content-Type":"application/json"}:{}),...init?.headers
  },
  signal:AbortSignal.timeout(10_000)
 });
 if(!response.ok){
  if(response.status===401||response.status===403||response.status===404)throw new GitHubAppError(response.status,"GitHub rejected the App request.");
  throw new GitHubAppError(response.status,"GitHub App API request failed.");
 }
 return await response.json() as T;
}
function appJwt():string{const c=configuration();return createGitHubAppJwt(c);}
export interface VerifiedGitHubInstallation {
 id:number;app_id:number;account:{id:number;login:string;type:"Organization"|"User"};
 repository_selection:"selected"|"all";permissions:Record<string,string>;target_id:number;
}
export function validateGitHubInstallation(installationId:number,result:VerifiedGitHubInstallation,expectedAppId:string):VerifiedGitHubInstallation {
 if(result.id!==installationId)throw new GitHubAppError(502,"GitHub returned a mismatched installation.");
 if(result.app_id!==Number(expectedAppId))throw new GitHubAppError(403,"The installation belongs to a different GitHub App.");
 if(!result.account||!Number.isSafeInteger(result.account.id)||!result.account.login||!["Organization","User"].includes(result.account.type))throw new GitHubAppError(502,"GitHub returned invalid installation account data.");
 if(result.repository_selection!=="selected")throw new GitHubAppError(403,"ChainProof requires explicitly selected repositories; reinstall the App with selected repository access.");
 if(result.permissions?.contents!=="read"||result.permissions?.metadata!=="read"||Object.entries(result.permissions).some(([name,permission])=>!["contents","metadata"].includes(name)||permission!=="read"))throw new GitHubAppError(403,"The GitHub App must have only read-only contents and metadata permissions.");
 return result;
}
export async function verifyGitHubInstallation(installationId:number):Promise<VerifiedGitHubInstallation>{
 const result=await githubRequest<VerifiedGitHubInstallation>(`/app/installations/${installationId}`,appJwt());
 return validateGitHubInstallation(installationId,result,env.GITHUB_APP_ID!);
}
async function createInstallationToken(installationId:number):Promise<string>{
 const token=await githubRequest<{token:string;expires_at:string}>(`/app/installations/${installationId}/access_tokens`,appJwt(),{method:"POST",body:JSON.stringify({permissions:{contents:"read",metadata:"read"}})});
 if(typeof token.token!=="string"||!token.token||!Number.isFinite(Date.parse(token.expires_at))||Date.parse(token.expires_at)<=Date.now())throw new GitHubAppError(502,"GitHub returned an invalid installation token.");
 return token.token;
}
export interface GitHubRepositorySummary {
 id:number;name:string;full_name:string;private:boolean;html_url:string;default_branch:string;
}
export async function listGitHubInstallationRepositories(installationId:number):Promise<{repositories:GitHubRepositorySummary[];totalCount:number;hasMore:boolean}>{
 const token=await createInstallationToken(installationId);
 const repositories:GitHubRepositorySummary[]=[];
 let totalCount=0;
 for(let page=1;page<=5;page++){
  const result=await githubRequest<{total_count:number;repositories:GitHubRepositorySummary[]}>(`/installation/repositories?per_page=100&page=${page}`,token);
  const parsed=z.object({total_count:z.number().int().nonnegative(),repositories:z.array(z.object({id:z.number().int().positive(),name:z.string().min(1).max(100),full_name:z.string().min(1).max(200),private:z.boolean(),html_url:z.string().url(),default_branch:z.string().min(1).max(255)}))}).safeParse(result);
  if(!parsed.success)throw new GitHubAppError(502,"GitHub returned an invalid repository list.");
  totalCount=parsed.data.total_count;
  repositories.push(...parsed.data.repositories);
  if(repositories.length>=totalCount||result.repositories.length===0)break;
 }
 return {repositories,totalCount,hasMore:repositories.length<totalCount};
}

export interface GitHubRepositorySnapshot {
 id:number;name:string;full_name:string;private:boolean;html_url:string;default_branch:string;
 pushed_at:string|null;updated_at:string;archived:boolean;disabled:boolean;
}
export interface GitHubBranchCommit {
 sha:string;commit:{committer:{date:string|null};author:{date:string|null};message:string};
}
export async function getGitHubRepositorySnapshot(input:{installationId:number;owner:string;repository:string}):Promise<{repository:GitHubRepositorySnapshot;commit:GitHubBranchCommit}> {
 const token=await createInstallationToken(input.installationId);
 const repository=await githubRequest<GitHubRepositorySnapshot>(`/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repository)}`,token);
 const parsedRepository=z.object({
  id:z.number().int().positive(),name:z.string().min(1).max(100),full_name:z.string().min(1).max(200),
  private:z.boolean(),html_url:z.string().url(),default_branch:z.string().min(1).max(255),
  pushed_at:z.string().datetime().nullable(),updated_at:z.string().datetime(),archived:z.boolean(),disabled:z.boolean()
 }).safeParse(repository);
 if(!parsedRepository.success||parsedRepository.data.id<=0)throw new GitHubAppError(502,"GitHub returned invalid repository metadata.");
 const commit=await githubRequest<GitHubBranchCommit>(`/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repository)}/commits/${encodeURIComponent(parsedRepository.data.default_branch)}`,token);
 const parsedCommit=z.object({
  sha:z.string().regex(/^[a-f0-9]{40}$/i),
  commit:z.object({committer:z.object({date:z.string().datetime().nullable()}),author:z.object({date:z.string().datetime().nullable()}),message:z.string().max(10000)})
 }).safeParse(commit);
 if(!parsedCommit.success)throw new GitHubAppError(502,"GitHub returned invalid default-branch commit metadata.");
 return {repository:parsedRepository.data,commit:parsedCommit.data};
}

export interface GitHubSbomFile { path:string;sha:string;size:number;content:Buffer; }
const MAX_SBOM_FILE_BYTES=1024*1024;
const MAX_SBOM_TOTAL_BYTES=5*1024*1024;
export async function getGitHubRepositorySbomFiles(input:{installationId:number;owner:string;repository:string;commitSha:string}):Promise<{files:GitHubSbomFile[];candidateCount:number;truncated:boolean}> {
 const token=await createInstallationToken(input.installationId);
 const tree=await githubRequest<{truncated:boolean;tree:Array<{path:string;mode:string;type:string;sha:string;size?:number}>}>(`/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repository)}/git/trees/${encodeURIComponent(input.commitSha)}?recursive=1`,token);
 const parsed=z.object({truncated:z.boolean(),tree:z.array(z.object({path:z.string().max(1024),mode:z.string(),type:z.string(),sha:z.string().regex(/^[a-f0-9]{40}$/i),size:z.number().int().nonnegative().optional()}))}).safeParse(tree);
 if(!parsed.success)throw new GitHubAppError(502,"GitHub returned an invalid repository tree.");
 let candidatePaths:string[];
 try{candidatePaths=boundedSbomCandidatePaths(parsed.data.tree,parsed.data.truncated);}catch(error){throw new GitHubAppError(422,error instanceof Error?error.message:"The repository tree exceeds discovery limits.");}
 const candidates=parsed.data.tree.filter(item=>candidatePaths.includes(item.path));
 const files:GitHubSbomFile[]=[];let totalBytes=0;
 for(const candidate of candidates){
  if(candidate.size===undefined||candidate.size<=0||candidate.size>MAX_SBOM_FILE_BYTES)continue;
  totalBytes+=candidate.size;
  if(totalBytes>MAX_SBOM_TOTAL_BYTES)throw new GitHubAppError(422,"Candidate SBOM files exceed the 5 MiB aggregate download limit.");
  const response=await githubRequest<{type:string;encoding:string;size:number;content:string;sha:string}>(`/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repository)}/contents/${candidate.path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(input.commitSha)}`,token);
  if(response.type!=="file"||response.encoding!=="base64"||response.sha!==candidate.sha||response.size!==candidate.size||typeof response.content!=="string")throw new GitHubAppError(502,"GitHub returned inconsistent SBOM file metadata.");
  const content=Buffer.from(response.content.replace(/\s/g,""),"base64");
  if(content.length!==candidate.size||content.length>MAX_SBOM_FILE_BYTES)throw new GitHubAppError(502,"GitHub returned an invalid or oversized SBOM file.");
  files.push({path:candidate.path,sha:candidate.sha,size:candidate.size,content});
 }
 return {files,candidateCount:candidates.length,truncated:false};
}
