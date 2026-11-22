# Contributing

Thanks for helping improve ChainProof.

## Development expectations

- Use TypeScript strict mode and keep domain boundaries explicit.
- Validate untrusted input at system boundaries.
- Add tests for behavior and security invariants when introducing domain functionality.
- Never execute repository content, package lifecycle scripts, or uploaded artifacts as part of ingestion.
- Never commit credentials, tokens, customer data, or production configuration.
- Keep changes focused and document material architecture decisions.

## Pull requests

Explain the problem, approach, security implications, and validation performed. Include screenshots for user-facing changes and migration notes for data-model changes.

## Commit messages

Prefer conventional prefixes such as feat, fix, docs, test, refactor, and chore.
