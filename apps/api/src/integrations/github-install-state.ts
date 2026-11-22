import {createHmac,randomBytes,timingSafeEqual} from "node:crypto";
import {z} from "zod";
const statePayloadSchema=z.object({
 organizationId:z.string().uuid(),
 userId:z.string().uuid(),
 nonce:z.string().regex(/^[a-f0-9]{64}$/),
 expiresAt:z.number().int()
}).strict();
const encode=(value:string)=>Buffer.from(value).toString("base64url");
function sign(payload:string,secret:string):string{return createHmac("sha256",secret).update("github-install-state:").update(payload).digest("base64url");}
export function createGitHubInstallState(input:{organizationId:string;userId:string;secret:string;now?:number;ttlSeconds?:number}):{state:string;nonce:string;expiresAt:Date}{
 const now=input.now??Math.floor(Date.now()/1000);
 const nonce=randomBytes(32).toString("hex");
 const payload=encode(JSON.stringify({organizationId:input.organizationId,userId:input.userId,nonce,expiresAt:now+(input.ttlSeconds??600)}));
 return {state:payload+"."+sign(payload,input.secret),nonce,expiresAt:new Date((now+(input.ttlSeconds??600))*1000)};
}
export function verifyGitHubInstallState(state:string,secret:string,now=Math.floor(Date.now()/1000)){
 if(state.length>2048)return null;
 const [payload,supplied,...extra]=state.split(".");
 if(!payload||!supplied||extra.length)return null;
 const expected=Buffer.from(sign(payload,secret)),actual=Buffer.from(supplied);
 if(expected.length!==actual.length||!timingSafeEqual(expected,actual))return null;
 try{
  const parsed=statePayloadSchema.parse(JSON.parse(Buffer.from(payload,"base64url").toString("utf8")));
  if(parsed.expiresAt<=now||parsed.expiresAt-now>900)return null;
  return parsed;
 }catch{return null;}
}
