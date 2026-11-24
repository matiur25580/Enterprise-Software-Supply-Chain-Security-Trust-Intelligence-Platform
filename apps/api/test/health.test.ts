import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/config/database", () => ({ isDatabaseConnected: vi.fn() }));
import { isDatabaseConnected } from "../src/config/database";
import { healthRouter } from "../src/routes/health";
const app = express();
app.use("/api/health", healthRouter);
describe("chainproof-api health probes", () => {
  beforeEach(() => vi.clearAllMocks());
  it("reports readiness only when the database is connected", async () => {
    vi.mocked(isDatabaseConnected).mockReturnValue(false);
    const notReady = await request(app).get("/api/health/ready");
    expect(notReady.status).toBe(503);
    expect(notReady.body.status).toBe("not-ready");
    vi.mocked(isDatabaseConnected).mockReturnValue(true);
    const ready = await request(app).get("/api/health/ready");
    expect(ready.status).toBe(200);
    expect(ready.body.status).toBe("ready");
  });
});
