import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import App from "./App";
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
describe("ChainProof dashboard", () => {
  it("shows a secure tenant sign-in and API status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true, json: async () => ({ status: "ok", database: "connected", service: "chainproof-api" })
    }));
    render(<App />);
    expect(screen.getByRole("heading", { name: /sign in to your workspace/i })).toBeTruthy();
    expect(screen.getByLabelText(/tenant id/i)).toBeTruthy();
    expect(screen.getByLabelText(/work email/i)).toBeTruthy();
    expect(await screen.findByText(/api online/i)).toBeTruthy();
  });
});