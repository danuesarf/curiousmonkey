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

## Space

`#/space` shows the estate as a tilted plane, replayed hour by hour over the last 24 hours (WIB).

- **Estate:** the plane is your organization, split into zones by environment (production, shared, staging, development, sandbox, each one colour). Each account is a ring with one star per busy role: higher and brighter = more calls in 7 days. Roles never called lie grey on the floor; the dashed grey part of a ring is that share. Identities outside the org that trust policies let in (other accounts, OIDC, SAML, `*`) float off the plane, placed by the trust map's worst finding: close and low = risky, far and high = pinned. Role chaining between accounts (a session whose parent session is in another connected account) arcs above the plane and lights up in the hours it happened; a pair first seen today is a white dashed NEW PATH. Changes from the feed mark the hour they happened on the bar.
- **One account:** the services the account calls stand as towers in the middle (taller = more calls in 7 days); roles cluster round the service they call most; accounts that chain in or out sit just past the edge; roles never called ring the floor.

Click anything for a card beside it; links go on from the card. Paths and their tags can be clicked too: a trust path shows the role it reaches, why the trust is flagged, who it trusts and on what conditions, and whether it was ever used. Drag or use the camera buttons to orbit; scroll or use + and − to zoom. The scale never changes on its own. Hours come from `track_sessions` (calls are counted in the hour their session started), heights from `activity_daily`. Red always means a problem and always carries a ⚠ tag.

## Event history

`#/events` searches every call your roles made through a session (assumed roles, Identity Center, OIDC, role chaining), kept for `SESSION_RETENTION_DAYS` (default 30). Calls by IAM users with long-term keys and by root are counted for analysis but not kept one by one; raw CloudTrail records are never stored.

Search with plain words, or keys: `role:`, `user:` (session name or caller), `ip:`, `action:`, `event:`, `resource:`, `error:`, `id:` (CloudTrail event ID), `key:` (access key), `agent:`. A leading `-` leaves matches out: `role:deploy -action:Describe`. Filter by account, denied or allowed, and time range; every filter is in the URL, so a search can be shared. Open a row for the full event and links to its session replay, the role, the same IP or the same event. **Download CSV** exports up to 5,000 matching calls and is recorded in the audit log.

## Planned accounts

An account can be added before anyone deploys the scanner role in it: **Accounts → Add planned account**, one at a time or pasted one per line (`account ID, name, environment, OU`). A planned account has no access settings and is never scanned or counted in the history bar. It shows on Space as a dashed ring, and the trust map counts it as one of yours, so trust from it is no longer shown as coming from outside the org. **Onboard** runs the usual connect wizard with its details filled in, then verifies it.

## Trust map

**Trust** in the rail lists every way into every role, read from the trust policies. Each (statement × principal) is one row, with:

- where it comes from: the same account, your other connected accounts, AWS accounts outside your estate, OIDC (GitHub Actions, Bitbucket Pipelines, GitLab, EKS service accounts, Terraform Cloud…), SAML, Google, AWS services, or anyone;
- the conditions on the way in, and what was actually seen coming in through it;
- findings: trusts a whole account (`:root`) instead of a role; principal `*` or `NotPrincipal`; an account outside your estate with no `sts:ExternalId`; OIDC with no `sub` condition, or a broad wildcard `sub`; no `aud`; SAML with no `SAML:aud`; an IAM user; a deleted identity; `sts:*`; never used.

Everything is a query, so a view is a shareable link and a CSV export:

```
finding:account-root                      roles that trust a whole account
from:123456789012                         roles that trust that account (or a connected account's name)
account:payments-prod source:oidc         OIDC ways into one account's roles
provider:github finding:oidc-broad-sub    GitHub Actions trust with a wildcard subject
source:external -cond:ExternalId          outside accounts with no ExternalId condition
role:deploy has:findings used:no          …
```

Keys: `account` `from` `source` `type` `provider` `finding` `severity` `role` `cond` `env` `has` `no` `used`; prefix `-` to exclude; anything else is free text.

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
