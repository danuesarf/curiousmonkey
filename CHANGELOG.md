# Changelog

## Unreleased

### Added
- **Password reset by an owner.** Members → *Reset password* makes a single-use link (24 hours, hash-only storage, token after the `#`) for the member to choose a new password. Using it signs them out everywhere and can reset their two-factor too. Owners only; audited as `member.password_reset_link` and `auth.password_reset`.
- **Single sign-on on the Configuration page.** Owners set OIDC there instead of only by environment variables, with a JumpCloud preset (issuer per region, scopes, group claim), the redirect and login URLs to copy, a *Check issuer* test and a warning when no group is mapped to a role. The client secret is stored encrypted and never returned. The sign-in button says which provider it is.
- **Light theme.** A sun/moon button in the top bar switches between the dark theme and a light one: the same design on pale mint paper with deep green ink, with banana kept for buttons and darkened to gold for text. The choice is kept per browser. Drawings (Space, Radar, Track, the sign-in radar) are mapped colour by colour, so every page follows the theme.
- **IAM Identity Center as one source.** Every account's `AWSSSO_<id>_DO_NOT_DELETE` SAML provider is matched to its Identity Center instance by the issuer in its metadata, and the Trust map and Space draw each instance once, with the account it is managed from.
- **Warnings for a second Identity Center.** An account that trusts more than one instance, or an instance other than the one most of your accounts use, is a high finding (`finding:idc-multiple`, `finding:idc-other`). Either can mean an account instance turned on inside a member account, or another organisation's.
- **Space: In, Out or Both.** A toggle shows only who can get into an account (outside identities, your other accounts, the scanner) or only where it can go. Paths between your accounts now include what trust policies allow, not only what was used: dashed when allowed but unused, red when the trust is risky.
- **Environments are yours to edit.** Add, rename, recolour, reorder or remove environments on the Configuration page. Removing one that accounts use asks where to move them.
- **Space: what you pick stands out.** Picking an account, role, service, outside identity or path keeps it and everything connected to it lit, and fades the rest. The page still opens with the whole scene lit.

### Changed
- **Space, easier to read.** The right-hand panel now leads with one sentence, the key numbers, then who can get in (from outside your org and from your other accounts, separately) and where it goes. With nothing picked it shows an overview and what to check first. The legend is folded away.
- **Windows instead of leaving the page.** Anything in Space that used to navigate away (calls, a role, the trust map, sessions) opens in a window over Space, marked with a window icon; it is loaded when opened and dropped when closed. Entries under "who can get in" and "where it goes" open the sessions or trust behind them.
- **A bell in the top bar** lists what needs a look in the last 24 hours, on every page.
- **Move the view** in Space: Shift+drag, right-drag, a sideways swipe, the arrow keys or the Move buttons.
- **Events and Space rebuilt for large estates.** Two small tables are written as calls arrive: how many calls of each kind every role made in each hour, and which sessions were active. A search now reads them first, so it skips hours with no match and reads only the sessions that can have one; a search with no match anywhere answers at once. On 20 million stored calls a rare search (`ssm:` denied over 7 days) went from 51 s to 0.5 s, and the first page from seconds to about 150 ms.
- Calls stored before the upgrade are counted in the background, newest day first; Events says how far back it has got. Until then older hours are searched the previous way.
- Space and the first page of Events are remembered for a few seconds in the API and refreshed in the background while someone is looking; the browser remembers both Space views, and fetches an account as soon as you pick it, so zooming in does not wait.
- A search gives up after about 12 seconds and returns what it has, then carries on as you scroll, instead of holding a database connection for a minute.
- Optional `DATABASE_READ_URL` sends Events and Space reads to a replica.
- The scanner policy now includes `iam:ListSAMLProviders` and `iam:GetSAMLProvider` (metadata only). Existing scanner roles keep working without them; until they are added, Identity Center instances are grouped as one and marked "instance not read yet".
- Events and Space are much faster on large estates (tens of millions of calls); two indexes are built without blocking writes on first start.

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
