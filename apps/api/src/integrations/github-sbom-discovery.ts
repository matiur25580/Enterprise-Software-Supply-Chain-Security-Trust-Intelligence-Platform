import {z} from "zod";
export const githubSbomDiscoveryParamsSchema=z.object({repositoryId:z.coerce.number().int().positive()}).strict();
export function isSupportedSbomCandidate(path:string):boolean {
 const fileName=path.toLowerCase().split("/").pop()??"";
 return fileName.endsWith(".cdx.json")||fileName.endsWith(".spdx.json")||fileName.endsWith(".sbom.json")||fileName==="sbom.json"||fileName==="bom.json"||fileName.endsWith(".cyclonedx.json");
}
export function boundedSbomCandidatePaths(entries:readonly {path:string;type:string}[],truncated:boolean):string[] {
 if(truncated)throw new Error("The GitHub repository tree is truncated.");
 if(entries.length>10000)throw new Error("The GitHub repository tree exceeds 10,000 entries.");
 const paths=entries.filter(entry=>entry.type==="blob"&&isSupportedSbomCandidate(entry.path)).map(entry=>entry.path);
 if(paths.length>10)throw new Error("The repository contains more than 10 candidate SBOM files.");
 return paths;
}
