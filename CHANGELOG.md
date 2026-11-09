# Changelog

## 0.1.0 · 2026-11-09

The first release of **Curious Monkey**: see what every IAM role in every AWS account really uses, who can get into it, and cut it down to least privilege with evidence. Self-hosted and read-only.

![Space](docs/screenshots/space.webp)

### What's in it

- **Radar**: every account (or every role in one account) at a glance: share of permissions never used, excess, 7- and 30-day trends, and pings for changes that matter.
- **Space**: the estate on a 3D plane, replayed hour by hour over the last 24 hours, with account-to-account paths and outside identities. Zoom into one account to see roles grouped by the service they call.
- **Trust map**: who can get into your AWS (outside accounts and vendors, GitHub Actions, Bitbucket, EKS, SAML, `*`) and your accounts trusting each other, coloured by risk, with findings such as whole-account trust, missing `sts:ExternalId`, or OIDC without a `sub` condition.
- **Roles**: granted vs. used vs. unverifiable permissions for every role, why it is high risk, who assumed it (with or without MFA), and the trust conditions they met.
- **Least-privilege recommendations**: drafted from the evidence (rules, or Amazon Bedrock if you enable it), checked, and approved by the security teams.
- **Track**: replay one session call by call, including role chaining across accounts. Also available from Space.
- **Event history**: search every call your roles made by role, user, IP, action, resource or error; export to CSV.
- **Sector scan**: one role cut into services and access levels.
- **Scanning**: Event History or an S3 trail (including organization trails), read incrementally with checkpoints, a separate worker that resumes after a crash, a daily scan plus catch-up reads every 30 minutes, planned accounts before onboarding.
- **Health**: database and worker health, with what to change.
- **Access**: owner, admin, reviewer, account owner and auditor roles; two-factor for anyone who can approve; SSO (OIDC); an audit log.

### Try it

```sh
git clone https://github.com/danuesarf/curiousmonkey && cd curiousmonkey
cp .env.example .env
perl -pi -e 's/^AWS_MODE=.*/AWS_MODE=demo/; s/^(POSTGRES_PASSWORD|SESSION_SECRET|DATA_ENCRYPTION_KEY)=$/$1 . "=" . `openssl rand -hex 32`/e' .env
docker compose up -d --build
docker compose exec app node src/cli.js demo
```

Open http://localhost:8080 and sign up; the first person becomes the owner. For real AWS accounts, leave `AWS_MODE=aws` and follow **Connecting an account** in the README. Kubernetes manifests are in `deploy/k8s`.

### Security

Every push is checked by tests, npm audit, Trivy (dependencies, configuration and the container image), Semgrep, Gitleaks and Checkov. The image runs as a non-root user without npm.

### Known limits

- MIT licensed.
- This is a 0.x release: the database schema may still change (migrations run automatically on start).
- Calls are kept one by one for `SESSION_RETENTION_DAYS` (default 30); counts per day are kept for the whole lookback.
- Event History reaches back 90 days; read from an S3 trail for longer.
