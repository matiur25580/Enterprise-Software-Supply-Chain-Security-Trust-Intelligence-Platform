import express, { Router, type Router as ExpressRouter } from "express";
import type { Request, Response, NextFunction } from "express";
import { env } from "../config/env.js";
import { GitHubWebhookDelivery } from "../models/github-webhook-delivery.js";
import {
  hashGitHubWebhookPayload,
  parseGitHubWebhookMetadata,
  verifyGitHubWebhookSignature
} from "../integrations/github-webhook-security.js";

export const githubWebhooksRouter: ExpressRouter = Router();

githubWebhooksRouter.post("/github",
  (request: Request, response: Response, next: NextFunction) => {
    if (!env.GITHUB_WEBHOOK_SECRET) {
      response.status(503).json({ error: { code: "WEBHOOK_NOT_CONFIGURED", message: "GitHub webhook intake is not configured." } });
      return;
    }
    next();
  },
  express.raw({ type: "application/json", limit: "1mb" }),
  async (request: Request, response: Response, next: NextFunction) => {
    const rawBody = request.body;
    if (!Buffer.isBuffer(rawBody)) {
      response.status(400).json({ error: { code: "INVALID_WEBHOOK_BODY", message: "A JSON webhook payload is required." } });
      return;
    }
    const signature = request.header("x-hub-signature-256");
    if (!verifyGitHubWebhookSignature(rawBody, signature, env.GITHUB_WEBHOOK_SECRET!)) {
      response.status(401).json({ error: { code: "INVALID_WEBHOOK_SIGNATURE", message: "The webhook signature is invalid." } });
      return;
    }
    const deliveryId = request.header("x-github-delivery");
    const eventName = request.header("x-github-event");
    if (!deliveryId || deliveryId.length > 128 || !/^[A-Za-z0-9-]+$/.test(deliveryId) ||
        !eventName || eventName.length > 100 || !/^[a-z_]+$/.test(eventName)) {
      response.status(400).json({ error: { code: "INVALID_WEBHOOK_HEADERS", message: "Required GitHub delivery headers are invalid." } });
      return;
    }
    const metadata = parseGitHubWebhookMetadata(eventName, rawBody);
    if (!metadata) {
      response.status(400).json({ error: { code: "INVALID_WEBHOOK_PAYLOAD", message: "The webhook payload is not valid JSON." } });
      return;
    }
    try {
      await GitHubWebhookDelivery.create({
        deliveryId, ...metadata, payloadSha256: hashGitHubWebhookPayload(rawBody),
        processingStatus: "queued", receivedAt: new Date()
      });
      response.status(202).json({ data: { accepted: true, duplicate: false, deliveryId } });
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === 11000) {
        response.status(202).json({ data: { accepted: true, duplicate: true, deliveryId } });
        return;
      }
      next(error);
    }
  }
);
