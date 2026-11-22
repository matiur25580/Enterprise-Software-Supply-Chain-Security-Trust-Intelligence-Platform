import mongoose,{Schema,model,type Model} from "mongoose";
const componentSchema=new Schema({
 bomRef:{type:String,default:null,maxlength:512},name:{type:String,required:true,maxlength:256},
 group:{type:String,default:null,maxlength:256},version:{type:String,default:null,maxlength:256},
 purl:{type:String,default:null,maxlength:1024},cpe:{type:String,default:null,maxlength:512},
 licenses:{type:[{type:String,maxlength:256}],default:[]}
},{_id:false,versionKey:false});
const sbomSchema=new Schema({
 sbomId:{type:String,required:true,unique:true,immutable:true},
 organizationId:{type:String,required:true,immutable:true},
 projectId:{type:String,required:true,immutable:true},
 format:{type:String,enum:["cyclonedx","spdx"],required:true,immutable:true},
 specVersion:{type:String,required:true,maxlength:32,immutable:true},
 serialNumber:{type:String,default:null,maxlength:256},
 documentName:{type:String,default:null,maxlength:256},
 documentSha256:{type:String,required:true,immutable:true,match:/^[a-f0-9]{64}$/},
 source:{type:String,enum:["manual","github"],default:"manual",required:true},
 sourceMetadata:{type:new Schema({repositoryId:{type:Number,default:null},repositoryFullName:{type:String,default:null,maxlength:200},path:{type:String,default:null,maxlength:1024},commitSha:{type:String,default:null,match:/^[a-f0-9]{40}$/i}},{_id:false,versionKey:false}),default:null},
 componentCount:{type:Number,required:true,min:0,max:5000},
 components:{type:[componentSchema],default:[]},
 uploadedByUserId:{type:String,required:true,immutable:true}
},{timestamps:true,versionKey:false});
sbomSchema.index({organizationId:1,projectId:1,documentSha256:1},{unique:true,name:"sboms_org_project_digest_unique"});
sbomSchema.index({organizationId:1,projectId:1,createdAt:-1},{name:"sboms_org_project_timeline"});
export const Sbom:Model<any>=(mongoose.models.Sbom as Model<any>|undefined)??model("Sbom",sbomSchema);
