**A fifth real source — a cloud IAM operation log, not an app, database, or IdP**

Cloudflare, MySQL, Suricata, and Auth0 cover a web app, a database, network IDS, and an identity provider. This one covers cloud infrastructure identity — real IAM API calls, captured from LocalStack (free, local AWS emulation, already used elsewhere in this portfolio for `aws-identity-detection`), relayed into Wazuh.

**Why LocalStack's request log, not CloudTrail**

LocalStack Community doesn't generate CloudTrail-format logs at all — that's a Pro-only feature, a real, already-documented limitation in `aws-identity-detection`'s own case study. What it does produce: its own plain-text request log, one line per API call — `AWS iam.CreateUser => 200`, `AWS iam.AttachUserPolicy => 200`, `AWS iam.CreateAccessKey => 200` — captured with `docker logs -f localstack-localstack-1`, filtered for the `localstack.request.aws` logger, and appended to a file Wazuh watches. Same on-demand pattern as this repo's other live sources: the relay runs for the duration of a test, then gets stopped, not left running unattended.

**Wazuh has no built-in AWS/CloudTrail decoder**

Same situation as Cloudflare and Auth0: `local_rules.xml` here is a custom rule set matching directly on the operation names in LocalStack's log text, since there's no structured JSON to decode against and no built-in AWS ruleset to lean on. The rules specifically target IAM operations that establish cloud-account persistence — `CreateUser`, `AttachUserPolicy`, `CreateAccessKey` — tagged with MITRE **T1078.004** (Valid Accounts: Cloud Accounts). `CreateAccessKey` gets the highest severity of the three (level 9 vs. level 7) since minting a new credential is the actual persistence mechanism; the user and policy steps are precursors to it.

**Why this exists: T1078.004's official Atomic Red Team tests can't run here**

All three official Atomic Red Team tests for T1078.004 require real cloud resource creation — two use GCP (service account, custom IAM role), one uses Azure (`New-AzAutomationRunbook`, needing `Connect-AzAccount` and a real `terraform apply` against a real subscription). None has a benign local-only variant, confirmed with a `-ShowDetails` dry-run before ruling that out. Rather than force a real-cloud-touching test just to check a box, this adapts the same underlying technique concept — a valid cloud identity creates a new, persistent credential — using AWS IAM against LocalStack instead. See `atomic-red-team-validation`'s T1078.004 case study for the full result and an explicit statement of what this does and doesn't prove relative to the official test.

**Running it**
```bash
docker start localstack-localstack-1

# relay: filter LocalStack's own log for AWS API calls, append to the watched file
docker logs -f localstack-localstack-1 2>&1 | grep --line-buffered 'localstack.request.aws' >> ~/securitylab/localstack-lab/wazuh-feed/localstack-requests.log &

# generate real activity
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url=http://localhost:4566 iam create-user --user-name backup-svc-account
aws --endpoint-url=http://localhost:4566 iam attach-user-policy --user-name backup-svc-account --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws --endpoint-url=http://localhost:4566 iam create-access-key --user-name backup-svc-account

# stop the relay when done, clean up the test user
kill %1
aws --endpoint-url=http://localhost:4566 iam detach-user-policy --user-name backup-svc-account --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws --endpoint-url=http://localhost:4566 iam delete-user --user-name backup-svc-account
```
Then check `docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json` on the Wazuh side to watch alerts land. `sample-alert.json` is a real alert this produced.
