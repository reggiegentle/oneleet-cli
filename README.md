# oneleet-cli

Agent-first private-surface CLI for Oneleet read workflows.

This is an unofficial adapter. It is not affiliated with, endorsed by, or an
official API wrapper for Oneleet. It uses Oneleet private web API surfaces and
can drift when Oneleet changes the app.

## Current scope

- browser/CDP-assisted auth import
- session health checks
- current user and tenant reads
- dashboard, HIPAA aggregate report, controls, monitors, evidence, policies, frameworks, people, vendors, domains, integrations, access reviews, risk assessments, security training, trust center, reports, pentests, code security, and attack-surface reads
- guarded evidence writes for uploading file evidence to controls and linking existing evidence to controls or vendors
- guarded risk reads/updates, control links, and archive/unarchive actions for assessment triage
- read-only `/api/v1/...` escape hatch for uncovered Oneleet private API paths

Mutations are limited to explicit workflow commands that are dry-run by default
and require `--write` plus an exact `--confirm ...` value.

## Install

Source checkout:

```bash
npm install
npm run build
node dist/cli.js --help
```

Published package install:

```bash
npm install -g oneleet-cli
oneleet --help
```

Skill install:

```bash
npx -y skills add -g danielgwilson/oneleet-cli --skill oneleet
```

One-off run:

```bash
npx -y oneleet-cli doctor --json
```

Optional local link:

```bash
npm link
```

## Auth

Requires Node.js 22 or newer.

Open a logged-in Chrome session with remote debugging enabled, then import the
`oneleet-app` session cookie:

```bash
oneleet auth import-cdp --port 9333 --json
oneleet doctor --json
```

The saved config lives at:

```text
~/.config/oneleet/config.json
```

It is written with `0600` permissions. Do not commit it.

Ephemeral env auth is also supported:

```bash
export ONELEET_APP_COOKIE=...
export ONELEET_TENANT_ID=...
oneleet doctor --json
```

Do not pass cookie values as CLI flags.

`ONELEET_API_BASE_URL` is only for synthetic local tests and must point at a
Oneleet HTTPS host by default. Non-Oneleet API hosts are rejected unless
`ONELEET_ALLOW_UNSAFE_API_BASE_URL=1` is set.

## Commands

```bash
oneleet auth status --json
oneleet auth clear --json
oneleet doctor --json
oneleet whoami --json
oneleet tenant get --json
oneleet dashboard --json
oneleet coverage check --json
oneleet hipaa report --json
oneleet hipaa report --format markdown --out /tmp/oneleet-hipaa.md --json
oneleet ops workforce-summary --json
oneleet vendor-risk report --json
oneleet trust readiness --json
oneleet security remediation-queue --json
oneleet monitors list --json
oneleet controls list --json
oneleet evidence list --json
oneleet evidence list --raw --json
oneleet evidence get <evidence-id> --json
oneleet evidence upload ./register.csv --control-id <control-id> --link-control-id <control-id> --json
oneleet evidence upload ./register.csv --control-id <control-id> --link-control-id <control-id> --write --confirm register.csv --json
oneleet evidence link-control <evidence-id> --control-id <control-id> --json
oneleet evidence link-control <evidence-id> --control-id <control-id> --write --confirm <evidence-id> --json
oneleet evidence link-vendor <evidence-id> --vendor-id <tenant-vendor-id> --json
oneleet evidence link-vendor <evidence-id> --vendor-id <tenant-vendor-id> --write --confirm <evidence-id> --json
oneleet policies list --json
oneleet policies types --json
oneleet frameworks list --json
oneleet access-reviews list --json
oneleet domains list --json
oneleet integrations list --json
oneleet risk-assessments list --json
oneleet risks get <risk-id> --json
oneleet risks update <risk-id> --response MITIGATE --response-details "Mitigation summary" --json
oneleet risks update <risk-id> --response MITIGATE --response-details "Mitigation summary" --write --confirm <risk-id> --json
oneleet risks controls <risk-id> --control-title "Audit logs collected" --json
oneleet risks controls <risk-id> --control-title "Audit logs collected" --write --confirm <risk-id> --json
oneleet risks archive <risk-id> --json
oneleet risks archive <risk-id> --write --confirm <risk-id> --json
oneleet risks unarchive <risk-id> --write --confirm <risk-id> --json
oneleet security-training modules --json
oneleet security-training progress --json
oneleet security-training progress --raw --json
oneleet people list --json
oneleet people list --raw --json
oneleet vendors list --json
oneleet trust config --json
oneleet trust documents --json
oneleet trust document-requests --json
oneleet trust faqs --json
oneleet trust security-issues --json
oneleet reports list --json
oneleet pentests active-request --json
oneleet code-security scan --json
oneleet code-security settings --json
oneleet code-security repositories --json
oneleet attack-surface summary --json
oneleet attack-surface issues --limit 50 --json
oneleet attack-surface scans --limit 50 --json
oneleet api get /api/v1/users/current --unsafe-raw --json
```

## Safety model

- private-surface, cookie-backed API
- read-only by default; write commands are opt-in and require `--write` plus exact confirmation
- refuses to send the session cookie to non-Oneleet API hosts unless explicitly opted into for synthetic local tests
- `api get` is an unsafe raw-output escape hatch and requires `--unsafe-raw`
- no raw HARs, screenshots, storage state, or full recon dumps in repo
- people, evidence, and security-training progress output is summarized by default; use `--raw` only when you need full upstream rows
- tenant, current-user, controls, monitors, vendors, domains, integrations, policies, access reviews, reports, trust-center rows, pentest requests, code-security rows, attack-surface issues, and attack-surface scans are also summarized by default where the upstream shape may contain sensitive or noisy details
- default summarized list rows use local `ref` values and `hasId` booleans instead of raw upstream IDs; pass `--raw` only for short-lived local debugging
- `coverage check`, `hipaa report`, `ops workforce-summary`, `vendor-risk report`, `trust readiness`, and `security remediation-queue` are intentionally aggregate/sanitized and avoid names, emails, cookies, URLs, UUID/internal IDs, and raw evidence filenames
- evidence and risk write commands intentionally return the affected evidence/risk IDs needed for follow-up writes, but never print cookies
- `hipaa report` includes `data.completeness`; treat `sourceErrors`, `shapeErrors`, or `paginationGaps` as report caveats before drawing conclusions

## Evidence write workflow

Evidence writes are meant for cases where a local artifact needs to become
control or vendor evidence without hand-clicking through Oneleet. Upload is
dry-run by default:

```bash
oneleet evidence upload ./control-evidence.csv \
  --control-id <primary-control-id> \
  --link-control-id <additional-control-id> \
  --link-control-id <another-control-id> \
  --reuse-existing-name \
  --json
```

To write, repeat the command with the generated confirmation string:

```bash
oneleet evidence upload ./control-evidence.csv \
  --control-id <primary-control-id> \
  --link-control-id <additional-control-id> \
  --link-control-id <another-control-id> \
  --reuse-existing-name \
  --write \
  --confirm control-evidence.csv \
  --json
```

Existing evidence can be linked without re-uploading:

```bash
oneleet evidence link-control <evidence-id> --control-id <control-id> --write --confirm <evidence-id> --json
oneleet evidence link-vendor <evidence-id> --vendor-id <tenant-vendor-id> --write --confirm <evidence-id> --json
```

## Risk write workflow

Risk writes are also dry-run first. Use `risks update` for risk text and
response fields:

```bash
oneleet risks update <risk-id> \
  --response MITIGATE \
  --response-details "Mitigate through audit logging, access review, and incident response controls." \
  --json
```

Control relationships can be managed by UUID or exact title. Title matching is
case-insensitive and errors on ambiguity:

```bash
oneleet risks controls <risk-id> \
  --control-title "Audit logs collected" \
  --control-title "Access reviews performed" \
  --json
```

To apply the relationship update:

```bash
oneleet risks controls <risk-id> \
  --control-title "Audit logs collected" \
  --control-title "Access reviews performed" \
  --write \
  --confirm <risk-id> \
  --json
```

Risks that should not remain in the active assessment can be archived with the
same guard:

```bash
oneleet risks archive <risk-id> --write --confirm <risk-id> --json
```

## Contract

See [docs/CONTRACT_V1.md](./docs/CONTRACT_V1.md).

## Release Hygiene

See [docs/PUBLISHING.md](./docs/PUBLISHING.md). The short gate is:

```bash
npm run check:release
```
