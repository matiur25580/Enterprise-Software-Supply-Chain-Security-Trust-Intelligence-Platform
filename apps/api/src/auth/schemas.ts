import { z } from "zod";

const email = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const password = z.string().min(12).max(128);
const slug = z.string().trim().toLowerCase().min(3).max(63).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);

export const registerSchema = z.object({
  email,
  password,
  displayName: z.string().trim().min(2).max(100),
  organizationName: z.string().trim().min(2).max(120),
  organizationSlug: slug
}).strict();

export const loginSchema = z.object({
  email,
  password: z.string().min(1).max(128),
  organizationSlug: slug
}).strict();

export const refreshSchema = z.object({ refreshToken: z.string().min(40).max(256) }).strict();
