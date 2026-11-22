import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { roles, type Role } from "./roles.js";

const sessionSchema = z.object({
  sub: z.string().uuid(),
  orgId: z.string().uuid(),
  sid: z.string().uuid(),
  roles: z.array(z.enum(roles)).min(1),
  iat: z.number().int(),
  exp: z.number().int()
});
export type SessionClaims = z.infer<typeof sessionSchema>;
const encode = (value: string) => Buffer.from(value).toString("base64url");

function signature(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function issueSession(input: { userId: string; organizationId: string; sessionId?: string; roles: readonly Role[]; secret: string; ttlSeconds?: number; now?: number }): string {
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const claims = sessionSchema.parse({
    sub: input.userId, orgId: input.organizationId, sid: input.sessionId ?? randomUUID(),
    roles: input.roles, iat: now, exp: now + (input.ttlSeconds ?? 900)
  });
  const payload = encode(JSON.stringify(claims));
  return payload + "." + signature(payload, input.secret);
}

export function verifySession(token: string, secret: string, now = Math.floor(Date.now() / 1000)): SessionClaims | null {
  if (token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const expected = Buffer.from(signature(parts[0], secret));
  const supplied = Buffer.from(parts[1]);
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
  try {
    const claims = sessionSchema.parse(JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")));
    if (claims.exp <= now || claims.iat > now + 60 || claims.exp - claims.iat > 86_400) return null;
    return claims;
  } catch { return null; }
}
