import {z} from "zod";
export const linkRepositorySchema=z.object({
 installationId:z.number().int().positive(),
 repositoryId:z.number().int().positive()
}).strict();
export const githubRepositoryIdSchema=z.number().int().positive();
export function repositoryBelongsToInstallation(input:{requestedRepositoryId:number;repositories:readonly {id:number}[]}):boolean{
 return input.repositories.some(repository=>repository.id===input.requestedRepositoryId);
}
