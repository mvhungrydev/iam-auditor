# Project: IAM Auditor
# Type: AWS DevOps Portfolio Project

## Design-First Workflow
Before writing any code or Terraform, create these 6 docs under docs/ in order:
1. `01-business-requirements.md` — problem, goals, FR/NFR, severity definitions
2. `02-value-proposition.md`    — why not existing tools, what this project adds
3. `03-technical-design.md`     — architecture, data flow, IAM policy, detection rules
4. `04-infrastructure-spec.md`  — Terraform module structure, schemas, variable layout
5. `05-cicd-pipeline-spec.md`   — GitHub Actions workflow, OIDC auth, branch protection
6. `06-development-plan.md`     — sequenced stories and tasks (local first)

All 5 design docs must be reviewed and approved before any code is written.

## Development Sequence
- Phase 1: Local dev environment (pytest + moto, Docker build)
- Phase 2: Lambda/application logic — TDD with moto, no real AWS
- Phase 3: Docker container — build + local RIE smoke test + Trivy scan
- Phase 4: Terraform — write all modules, validate + checkov + bandit locally
- Phase 5: AWS first deploy — first time touching real AWS
- Phase 6: CI/CD pipeline — GitHub Actions, OIDC, branch protection

## Terraform Convention
Always use the envs/ pattern — never a flat root module:
```
infra/
├── modules/     ← all reusable logic
└── envs/
    ├── dev/     ← dev entrypoint (main.tf, backend.tf, terraform.tfvars)
    └── prod/    ← prod entrypoint
```

## Key Rules
- Never commit `*.tfvars` — use `terraform.tfvars.example` as a committed template
- `.terraform.lock.hcl` MUST be committed (dependency lock file — like package-lock.json)
- `.venv/` is always gitignored — regenerated via `setup.sh`
- No AWS credentials stored anywhere — CI/CD uses GitHub OIDC only
- Always update `docs/06-development-plan.md` whenever the development plan changes
