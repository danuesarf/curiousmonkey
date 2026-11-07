# Curious Monkey

> The monkey only needs a banana. Don't give it a bazooka.

Curious Monkey works like AWS IAM Access Analyzer, across many AWS accounts. For every IAM role it shows who used it (and which trust-policy conditions they met on the way in), what they did (CloudTrail event history, stored incrementally), and a least-privilege policy drafted from that evidence. Permissions it cannot verify from event history are flagged instead of silently dropped.

## Run it

Needs Docker. The scanner runs in its **own container**, so a heavy scan never slows the portal or API.

```sh
cp .env.example .env            # set POSTGRES_PASSWORD, SESSION_SECRET, DATA_ENCRYPTION_KEY (openssl rand -base64 48)
docker compose up --build       # postgres, app (UI + API), worker
```

Open http://localhost:8080 (change `HOST_PORT` in `.env` if the port is taken) and sign up. **The first person to sign up becomes the owner.** After that, sign-up is by invite link only.

Try it without AWS credentials: set `AWS_MODE=demo` in `.env`, then `docker compose exec app node src/cli.js demo`. This adds two fake accounts and queues their first scans.

Kubernetes: `kubectl apply -k deploy/k8s` (copy `secret.example.yaml` to a real secret first). The API and the worker are separate Deployments; scale workers with `replicas`.

## How the scanner works

- Scans are jobs in a Postgres queue (`FOR UPDATE SKIP LOCKED`). Steps: inventory, events (one job per region), Access Advisor, analyze.
- A job holds a 90 s lease, renewed by heartbeat. If a worker dies, the reaper requeues the job and another worker continues from the saved checkpoint. Failures retry with backoff (30 s doubling to 30 min, 5 attempts). Permission errors fail at once and are not retried.
- Event history is read in 6-hour slices. Each slice commits its aggregates and checkpoint together, so a restart never re-reads saved history or double counts. A daily scan reads only what is new.
- CloudTrail Event History keeps 90 days. If the worker is down longer than that, the gap is shown on the account page.
- Monitor everything under **Scans** (workers, queue, per-job progress, logs, retry, cancel). Prometheus metrics are on the worker at `:8081/metrics`.

## Connecting an account

The **Connect an AWS account** wizard has four steps. Nothing is saved until the last one.

1. **Account**: name, account ID, environment, regions.
2. **CloudTrail source**:
   - **Event History** works out of the box. It covers at most 90 days, holds management events only, and is slow, because AWS allows 2 requests a second (about 100 events a second per region).
   - **S3 trail** reads the trail's log files. It has no request limit, so it usually takes minutes. History goes as far back as the files exist (up to 2 years here), and it includes data events if the trail logs them.
   - The wizard estimates the first scan's duration. Scan activity shows a live ETA while it runs.
3. **Access**:
   - **Assume a scanner role** (recommended). The base identity is either the worker's own credentials (instance, task or pod role, or keys in `.env`) or an access key stored encrypted on the account.
   - **IAM user access key**: the keys of a dedicated read-only user, used directly.
4. **Deploy and connect**: apply the Terraform or CloudFormation template, then connect. You land on Scan activity.

Edit an account at any time. Switching source keeps the stored history. Widening the lookback backfills only the older days. The worker logs which AWS identity it runs as at startup, and the wizard shows it.

## The radar

The portal opens on a **radar** with three views:

- **Estate:** each contact is an AWS account. Distance from the centre is its share of permissions never called; size is its excess permissions (granted minus used). A trail shows where it was 7 and 30 days ago: amber when drifting outward (getting worse), green when moving inward. The sweep stands for the last 24 hours: a contact echoes as the sweep passes, brighter with more calls. Pings mark changes that matter. Sectors are environments, or the OU / group you set on each account.
- **Account:** the same for one account's roles, sectored by role kind.
- **Blast radius:** pick an identity (a user, an SSO or OIDC identity, a role); the radar shows every role it can reach, ring by ring: roles it was seen entering or whose trust policy names it, then the same again from each role reached (role chaining), up to 4 hops, across accounts. It does not yet check that each role holds `sts:AssumeRole` on the next, so a trust-only (dashed) edge is a possibility, not a proven path. AWS service principals are left out: they are not identities anyone can steal.

**What changed** comes from two tables. After each final analysis of a fully read account, every role gets a daily snapshot (`role_snapshots`); trails and trends compare against them, so they appear after 7 and 30 days. The same step records changes (`changes`): permissions grew (or reached admin level), trimmed, first denied calls, went 90 days without calls, new roles, new unidentified event names. A caller seen entering a role for the first time is recorded while events are read. Nothing is recorded during an account's first read, when everything would look new. The feed marks what arrived since you last looked. In demo mode, `node src/cli.js demo-history` invents 35 days of snapshots and a few changes so this can be seen at once.

- **Sector scan** cuts one role into rings (access level) and sectors (service). Lit dots were called, amber dots are unconfirmed, dim dots were never called.
- **Track** replays one role session call by call. Each session is a lane. When a session assumes another role (role chaining), the call is drawn as a jump into a new lane for the new session, linked by access key. Chains across connected accounts are linked too. Sessions in accounts you can't see are counted, not shown. Session replays are kept for `SESSION_RETENTION_DAYS` (default 30).

### Results while history is still loading

The radar and role pages show data as soon as the first slices are read. Until an account's history is fully read, its results are marked **provisional**: used counts are "at least", never-called counts are "at most". The status bar shows how much is read and the time left. A provisional analysis runs every `PROVISIONAL_EVERY_SECONDS` (default 300). **Approval is blocked until history is complete.**

## Unidentified calls

Each account has an **Unidentified calls** page. It accounts for every CloudTrail event read: role sessions, role calls, and events outside scope (IAM users, root, services, roles the account doesn't have). It also covers three cases that need care:

- **Role found by name:** some events have no `sessionIssuer`, so the role is recovered from the session ARN.
- **Unidentified event names:** CloudTrail event names don't always match IAM action names. Known mismatches are handled, including versioned names like `GetDistribution2020_05_31`.
  - Calls under an unknown name are kept under the raw name, and the rest of that service stays *unconfirmed*, never *unused*. The draft holds those permissions back and says so.
  - Settle each name in one of four ways: type the action, **Ask Bedrock** (`BEDROCK_ENABLED=true`; a reviewer accepts each suggestion, and only real IAM actions are accepted), **No permission**, or **Can't resolve** with a note. A can't-resolve name reopens after 30 days if it is still being called.
  - A decision applies to every account and credits history already stored. No rescan is needed, only a re-analysis. The same panel opens from a role (**Identify**).
- **Calls that named no resource:** CloudTrail fills in `resources` for some events only. If any call of an action named no resource, the draft keeps that action's granted resources instead of narrowing to the ones seen, and the replay check enforces it.

Only event names and request parameter *names* are kept, never parameter values.

## Access

Roles: owner, admin, reviewer, account owner, auditor. Reviewers belong to Infrastructure Security or Information Security. Identity Center roles go to Information Security, service-linked roles to Infrastructure Security. High-risk roles need both teams. Everything can be limited to some accounts. Sign-in uses scrypt passwords, TOTP two-factor (required for privileged roles) and an audit log.

## What it does not do (be aware)

- It never changes your AWS accounts. Approved policies are exported as JSON or Terraform for you to apply.
- Data events (S3 objects, DynamoDB items) are not in Event History. Those permissions show as *unconfirmed*, not unused. Data-event source discovery is informational.
- Not built: SAML, SCP analysis, pull request creation, email delivery of invites (the invite is a link you send).
- Not tested against live services: the real AWS SDK paths, OIDC sign-in, and live Bedrock. Everything else is covered by tests run on a real Postgres with a built-in fake AWS estate (`npm test`).

## Develop

```sh
npm ci
npm test                        # needs the postgres binaries from embedded-postgres; run as a non-root user
npm start & npm run worker
```
