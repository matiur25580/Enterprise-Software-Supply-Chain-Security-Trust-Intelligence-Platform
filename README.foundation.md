# Milestone 1 — Foundation notes

The primary product overview remains in the root README.

## Delivered in this milestone

- pnpm workspace with Turborepo task orchestration
- React/Vite web application shell
- Express 5 API bootstrap with strict environment validation
- Helmet, explicit CORS origin, JSON payload cap, structured logging, and log redaction
- Local MongoDB and Redis development services
- Initial CI workflow, contribution guidance, security policy, and architecture threat model

## Deliberately deferred

Authentication, tenant-aware persistence, migrations, queue workers, external integrations, production deployment manifests, and formal security certification are not represented as complete. They will be introduced with dedicated tests and operational controls in later milestones.

## Local startup

1. Install Node.js 22+ and pnpm 10+.
2. Copy .env.example to .env and review the local-only defaults.
3. Start dependencies: docker compose -f infra/docker-compose.yml up -d
4. Install packages: pnpm install
5. Start both applications: pnpm dev
6. Open http://localhost:5173; API health: http://localhost:4000/api/v1/health

The API currently validates its bootstrap configuration only. Database and Redis connection lifecycle management will be added in the persistence milestone.
