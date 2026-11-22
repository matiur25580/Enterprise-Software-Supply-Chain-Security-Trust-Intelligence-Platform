import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const PARAMETERS = { N: 16384, r: 8, p: 1 } as const;

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12 || password.length > 128) throw new Error("Password must be between 12 and 128 characters.");
  const salt = randomBytes(SALT_LENGTH);
  const derived = (await scrypt(password, salt, KEY_LENGTH, PARAMETERS)) as Buffer;
  return ["scrypt", PARAMETERS.N, PARAMETERS.r, PARAMETERS.p, salt.toString("base64url"), derived.toString("base64url")].join("$");
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, n, r, p, saltText, hashText, extra] = encoded.split("$");
  if (algorithm !== "scrypt" || !n || !r || !p || !saltText || !hashText || extra !== undefined) return false;
  const salt = Buffer.from(saltText, "base64url");
  const expected = Buffer.from(hashText, "base64url");
  if (Number(n) !== PARAMETERS.N || Number(r) !== PARAMETERS.r || Number(p) !== PARAMETERS.p) return false;
  if (salt.length !== SALT_LENGTH || expected.length !== KEY_LENGTH) return false;
  try {
    const actual = (await scrypt(password, salt, KEY_LENGTH, { N: Number(n), r: Number(r), p: Number(p) })) as Buffer;
    return timingSafeEqual(actual, expected);
  } catch { return false; }
}
