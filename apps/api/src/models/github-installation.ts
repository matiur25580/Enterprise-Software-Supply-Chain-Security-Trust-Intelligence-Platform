import mongoose,{Schema,model,type Model} from "mongoose";
const stateSchema=new Schema({
 nonce:{type:String,required:true,unique:true,immutable:true},
 organizationId:{type:String,required:true,immutable:true},
 userId:{type:String,required:true,immutable:true},
 expiresAt:{type:Date,required:true}
},{timestamps:{createdAt:true,updatedAt:false},versionKey:false});
stateSchema.index({expiresAt:1},{expireAfterSeconds:0,name:"github_install_state_ttl"});
export const GitHubInstallState:Model<any>=(mongoose.models.GitHubInstallState as Model<any>|undefined)??model("GitHubInstallState",stateSchema);
const installationSchema=new Schema({
 installationId:{type:Number,required:true,unique:true,immutable:true},
 organizationId:{type:String,required:true,immutable:true,unique:true},
 accountId:{type:Number,default:null},
 accountLogin:{type:String,default:null,maxlength:100},
 accountType:{type:String,enum:["Organization","User",null],default:null},
 appId:{type:Number,default:null},
 repositorySelection:{type:String,enum:["selected","all",null],default:null},
 permissions:{type:Schema.Types.Mixed,default:{}},
 status:{type:String,enum:["pending_verification","active","suspended","removed"],default:"pending_verification",required:true},
 connectedByUserId:{type:String,required:true,immutable:true},
 verifiedAt:{type:Date,default:null}
},{timestamps:true,versionKey:false});
installationSchema.index({organizationId:1,status:1},{name:"github_install_org_status"});
export const GitHubInstallation:Model<any>=(mongoose.models.GitHubInstallation as Model<any>|undefined)??model("GitHubInstallation",installationSchema);
