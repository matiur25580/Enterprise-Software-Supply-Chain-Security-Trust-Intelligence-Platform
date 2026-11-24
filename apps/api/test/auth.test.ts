import express from "express";
import { rateLimit } from "express-rate-limit";
import jwt from "jsonwebtoken";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/models/User", () => ({ User: { findOne: vi.fn() } }));
import { User } from "../src/models/User";
import { authenticate } from "../src/middleware/authenticate";
import { authorize } from "../src/middleware/authorize";
const secret = "unit-test-secret-that-is-long-enough-for-hmac";
const app = express();
app.get("/protected", rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false }), authenticate, authorize("platform-admin"), (req, res) => res.json({ tenantId: req.auth!.tenantId }));
function token(claims: Record<string, unknown> = {}) {
  return jwt.sign({ tenantId: "tenant-a", role: "platform-admin", ...claims }, secret, { subject: "user-1", issuer: "chainproof-api", audience: "chainproof-client", expiresIn: "5m" });
}
describe("ChainProof authentication and authorization", () => {
  beforeEach(() => { vi.clearAllMocks(); vi.stubEnv("JWT_SECRET", secret); });
  it("rejects missing bearer tokens", async () => {
    const response = await request(app).get("/protected");
    expect(response.status).toBe(401);
    expect(User.findOne).not.toHaveBeenCalled();
  });
  it("revalidates the user inside the token tenant before allowing access", async () => {
    const select = vi.fn().mockResolvedValue({ _id: "user-1", tenantId: "tenant-a", role: "platform-admin" });
    vi.mocked(User.findOne).mockReturnValue({ select } as never);
    const response = await request(app).get("/protected").set("Authorization", `Bearer ${token()}`);
    expect(response.status).toBe(200);
    expect(response.body.tenantId).toBe("tenant-a");
    expect(User.findOne).toHaveBeenCalledWith({ _id: "user-1", tenantId: "tenant-a", active: true });
  });
  it("rejects a token if its account is inactive or missing", async () => {
    const select = vi.fn().mockResolvedValue(null);
    vi.mocked(User.findOne).mockReturnValue({ select } as never);
    const response = await request(app).get("/protected").set("Authorization", `Bearer ${token()}`);
    expect(response.status).toBe(401);
  });
  it("rejects expired or wrong-audience tokens", async () => {
    const expired = jwt.sign({ tenantId: "tenant-a" }, secret, { subject: "user-1", issuer: "chainproof-api", audience: "chainproof-client", expiresIn: -1 });
    const response = await request(app).get("/protected").set("Authorization", `Bearer ${expired}`);
    expect(response.status).toBe(401);
  });
  it("denies authenticated users without the required role", async () => {
    const select = vi.fn().mockResolvedValue({ _id: "user-1", tenantId: "tenant-a", role: "developer" });
    vi.mocked(User.findOne).mockReturnValue({ select } as never);
    const response = await request(app).get("/protected").set("Authorization", `Bearer ${token({ role: "developer" })}`);
    expect(response.status).toBe(403);
  });
});