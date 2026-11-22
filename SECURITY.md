# Security Policy

## Reporting a vulnerability

Do not disclose exploitable details, credentials, private package metadata, or customer artifacts in public issues. Use GitHub's private vulnerability reporting channel when available. Include affected components, impact, safe reproduction steps, and redacted evidence.

## Security requirements

- Treat repositories, SBOMs, packages, build artifacts, attestations, and webhook payloads as untrusted.
- Never execute untrusted source or artifacts inside the API process or with privileged credentials.
- Verify artifact digests, signer identity, provenance, and policy inputs cryptographically before making trust decisions.
- Keep AI-generated explanations advisory; deterministic verification and policy evaluation remain authoritative.
- Isolate tenants and enforce authorization server-side for every resource.
- Bound ingestion size, execution time, retries, and external requests.
- Store secrets outside source control and redact them from logs and traces.
- Preserve audit records for policy versions, evidence, overrides, and release decisions.
- Use disposable, least-privilege workers for any future analysis of untrusted artifacts.

## Project status

This repository is in its foundation phase. The policy describes design expectations, not implemented controls or a security certification.
