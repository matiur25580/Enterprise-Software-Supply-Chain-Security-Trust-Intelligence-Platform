import { randomBytes, scrypt as scryptCallback, timingSafeEqual, type ScryptOptions } from "node:crypto";

const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const PARAMETERS = { N: 16384, r: 8, p: 1 } as const;

function deriveKey(password: string, salt: Buffer, keyLength: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12 || password.length > 128) throw new Error("Password must be between 12 and 128 characters.");
  const salt = randomBytes(SALT_LENGTH);
  const derived = await deriveKey(password, salt, KEY_LENGTH, PARAMETERS);
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
    const actual = await deriveKey(password, salt, KEY_LENGTH, PARAMETERS);
    return timingSafeEqual(actual, expected);
  } catch { return false; }
}
