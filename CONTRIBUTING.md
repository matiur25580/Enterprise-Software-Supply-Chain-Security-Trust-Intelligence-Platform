# Contributing

Contributions to ChainProof should preserve the distinction between cryptographic verification, deterministic policy decisions, and advisory AI-generated explanations.

## Before starting
- Read README.md and SECURITY.md.
- Propose an architecture decision for changes that affect trust boundaries, ingestion, or policy semantics.
- Never commit credentials, private source code, customer SBOMs, proprietary artifacts, or vulnerability data that is not public.

## Engineering expectations
- Treat all uploaded artifacts and remote metadata as untrusted.
- Keep artifact parsing and analysis isolated from privileged API processes.
- Verify digests and signer identities before accepting provenance claims.
- Make ingestion bounded, idempotent, observable, and safe to retry.
- Add tests for malformed inputs, authorization, tenant isolation, and verification failures.
- AI output must not override cryptographic checks or policy outcomes.

## Pull requests
Document the threat-model impact, tests and commands run, supported formats, failure behavior, and any limitations. Avoid claims of SLSA conformance or security assurance unless verified against the relevant requirements.
