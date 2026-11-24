import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import { connectDatabase } from "../apps/api/src/config/database";
import { User } from "../apps/api/src/models/User";

const allowedRoles = ["platform-admin","security-analyst","developer","auditor"] as const;

async function main(): Promise<void> {
  const tenantId = process.env.USER_TENANT_ID?.trim();
  const email = process.env.USER_EMAIL?.trim().toLowerCase();
  const password = process.env.USER_PASSWORD;
  const role = process.env.USER_ROLE;

  if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is required.");
  if (!tenantId || !email || !password || !role) {
    throw new Error("Set USER_TENANT_ID, USER_EMAIL, USER_PASSWORD and USER_ROLE.");
  }
  if (password.length < 12) throw new Error("USER_PASSWORD must contain at least 12 characters.");
  if (!allowedRoles.includes(role as (typeof allowedRoles)[number])) {
    throw new Error(`USER_ROLE must be one of: ${allowedRoles.join(", ")}`);
  }

  await connectDatabase();
  const passwordHash = await bcrypt.hash(password, 12);
  await User.create({
    tenantId,
    email,
    passwordHash,
    role,
    active: true
  });
  console.info(`Created ${role} account for ${email} in tenant ${tenantId}.`);
}

void main()
  .catch((error: unknown) => {
    console.error("User provisioning failed:", error instanceof Error ? error.message : "unknown error");
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
