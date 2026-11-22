# GitHub source-control integration — webhook ingress foundation

## Scope

This milestone establishes a hardened inbound webhook boundary. It does not yet install GitHub Apps, exchange installation tokens, connect a repository to a tenant, clone/fetch source code, or execute repository content. Those operations require an explicit tenant-authorized connection workflow and a managed secret-encryption/KMS design.

## Endpoint

- `POST /api/v1/webhooks/github`
- Configure `GITHUB_WEBHOOK_SECRET` with the webhook secret generated in GitHub App settings.
- GitHub sends `X-Hub-Signature-256`, `X-GitHub-Delivery`, and `X-GitHub-Event`.
- The endpoint verifies HMAC-SHA256 over the exact raw request bytes before parsing payload metadata.
- Invalid signatures are rejected; missing configuration fails closed with 503.
- Body size is capped at 1 MiB and delivery/event headers are strictly bounded.

## Idempotency and data minimization

A unique delivery ID prevents duplicate delivery records. Duplicate deliveries receive an accepted response without creating a second record. The database stores only event/action and numeric provider identifiers plus a SHA-256 payload fingerprint; raw webhook bodies, repository contents, access tokens, and private keys are never persisted by this endpoint.

The delivery record is a durable intake ledger, not a completed job queue. A later worker must claim queued records atomically, apply retry/backoff and dead-letter policies, and reconcile provider state before making tenant changes.

## Security boundaries and next work

- Never trust installation or repository IDs as tenant authorization.
- Do not accept installation ownership from webhook payloads; tenant binding must come from an authenticated, explicit organization connection flow.
- Verify webhook signatures before JSON parsing or any state mutation.
- Enforce unique delivery IDs and retain delivery records under an explicit retention policy.
- Next: GitHub App installation callback/state validation, installation-to-tenant authorization, encrypted token storage backed by KMS/secret manager, least-privilege permissions, repository allowlisting, and asynchronous reconciliation.
- Repository URLs in the project registry remain descriptive metadata and are not fetched or executed.
