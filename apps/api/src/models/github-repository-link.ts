import mongoose,{Schema,model,type Model} from "mongoose";
const schema=new Schema({
 organizationId:{type:String,required:true,immutable:true},
 projectId:{type:String,required:true,immutable:true},
 installationId:{type:Number,required:true,immutable:true},
 repositoryId:{type:Number,required:true,immutable:true},
 ownerLogin:{type:String,required:true,maxlength:100},
 name:{type:String,required:true,maxlength:100},
 fullName:{type:String,required:true,maxlength:200},
 htmlUrl:{type:String,required:true,maxlength:2048},
 defaultBranch:{type:String,required:true,maxlength:255},
 isPrivate:{type:Boolean,required:true},
 status:{type:String,enum:["active","suspended","removed"],default:"active",required:true},
 linkedByUserId:{type:String,required:true,immutable:true},
 lastSyncedAt:{type:Date,default:null},
 lastSyncedCommitSha:{type:String,default:null,match:/^[a-f0-9]{40}$/i},
 lastSyncedCommitAt:{type:Date,default:null},
 syncStatus:{type:String,enum:["never","syncing","succeeded","failed"],default:"never"},
 syncError:{type:String,default:null,maxlength:300}
},{timestamps:true,versionKey:false});
schema.index({organizationId:1,repositoryId:1},{unique:true,name:"github_repo_org_repository_unique"});
schema.index({organizationId:1,projectId:1,status:1},{name:"github_repo_project_status"});
schema.index({installationId:1,status:1},{name:"github_repo_installation_status"});
export const GitHubRepositoryLink:Model<any>=(mongoose.models.GitHubRepositoryLink as Model<any>|undefined)??model("GitHubRepositoryLink",schema);
