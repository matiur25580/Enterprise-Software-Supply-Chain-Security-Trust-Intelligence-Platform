import {createSign} from "node:crypto";
import {env} from "../config/env.js";
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
export async function verifyGitHubInstallation(installationId:number):Promise<VerifiedGitHubInstallation>{
 const result=await githubRequest<VerifiedGitHubInstallation>(`/app/installations/${installationId}`,appJwt());
 if(result.id!==installationId)throw new GitHubAppError(502,"GitHub returned a mismatched installation.");
 if(result.app_id!==Number(env.GITHUB_APP_ID))throw new GitHubAppError(403,"The installation belongs to a different GitHub App.");
 if(!result.account||!Number.isSafeInteger(result.account.id)||!result.account.login||!["Organization","User"].includes(result.account.type))throw new GitHubAppError(502,"GitHub returned invalid installation account data.");
 if(result.repository_selection!=="selected")throw new GitHubAppError(403,"ChainProof requires explicitly selected repositories; reinstall the App with selected repository access.");
 if(result.permissions?.contents!=="read"||result.permissions?.metadata!=="read")throw new GitHubAppError(403,"The GitHub App must have read-only contents and metadata permissions.");
 return result;
}
async function createInstallationToken(installationId:number):Promise<string>{
 const token=await githubRequest<{token:string;expires_at:string}>(`/app/installations/${installationId}/access_tokens`,appJwt(),{method:"POST",body:"{}"});
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
  if(!Number.isSafeInteger(result.total_count)||!Array.isArray(result.repositories))throw new GitHubAppError(502,"GitHub returned an invalid repository list.");
  totalCount=result.total_count;
  repositories.push(...result.repositories.map((r)=>({
   id:r.id,name:r.name,full_name:r.full_name,private:r.private,html_url:r.html_url,default_branch:r.default_branch
  })));
  if(repositories.length>=totalCount||result.repositories.length===0)break;
 }
 return {repositories,totalCount,hasMore:repositories.length<totalCount};
}
