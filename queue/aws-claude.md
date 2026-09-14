# Claude Code on Amazon Bedrock — Setup Guide for a Shared AWS Account

**Audience:** DevSecOps / cloud platform engineer
**Scenario:** single shared AWS account, some developers already hold a `PowerUserAccess` permission set, Claude Code must be granted through a narrow path without degrading console access for power users.

**Assumptions used throughout — replace before running anything:**

| Placeholder | Example | Meaning |
|---|---|---|
| `<ACCOUNT_ID>` | `123456789012` | Your shared AWS account |
| `<REGION>` | `eu-west-1` | Bedrock source region |
| `<PREFIX>` | `eu` | Cross-region inference profile prefix |
| `<TEAM>` | `platform` | Cost-allocation unit |
| `<SSO_START_URL>` | `https://d-9067xxxxxx.awsapps.com/start` | IAM Identity Center portal |

---

## 0. Design decisions — read this before touching the console

### 0.1 The PowerUser overlap: what is and isn't achievable

`PowerUserAccess` grants `bedrock:*`. A developer holding it can invoke any Claude model from the CLI regardless of what you build below. **IAM cannot distinguish "PowerUser in the Bedrock console" from "PowerUser running Claude Code"** — both are SigV4 `InvokeModelWithResponseStream` calls from the same principal. Anyone telling you otherwise is selling something.

So the design splits into three layers:

| Layer | Control | Binds power users? | Breaks their console? |
|---|---|---|---|
| **Preventive** | Dedicated least-privilege permission set for Claude Code | No | No |
| **Preventive** | Deny `bedrock:CallWithBearerToken` account-wide | **Yes** | **No** |
| **Detective** | CloudTrail rule: Bedrock invoke not routed through an approved application inference profile | Yes | No |

The second row is the important one and is easy to miss. Any principal with a console session — including a power user — can mint a **short-term Bedrock API key** (a client-side pre-signed URL, valid up to 12 hours, no CloudTrail event at creation) and paste it into `AWS_BEARER_TOKEN_BEDROCK`. That bypasses your permission set entirely and produces credentials you cannot revoke individually. Denying `bedrock:CallWithBearerToken` closes it and has **zero effect on the Bedrock console**, which uses the session, not a bearer token.

### 0.2 Target architecture

```
IAM Identity Center
├── permission set "PowerUser"          → unchanged + DenyBedrockBearerTokens
└── permission set "ClaudeCodeBedrock"  → ClaudeCodeBedrockInvoke (4h session)
                                              │
                                              ▼
                            application-inference-profile/claude-code-<TEAM>
                              (tagged CostCenter=<TEAM>, Tool=claude-code)
                                              │
                                              ▼
                              eu.anthropic.claude-* (cross-region)
```

Everything a developer's Claude Code session can do in AWS is: invoke Claude through one tagged inference profile. Nothing else.

---

# Part 1 — Account setup (once, by an administrator)

## Step 1 — Enable Anthropic model access

Account-wide and non-restrictive; it does not affect existing power users.

1. Open the [Amazon Bedrock console](https://console.aws.amazon.com/bedrock/) in `<REGION>`.
2. Go to **Model catalog**, select an Anthropic model, and complete the **use case form**. Access is granted immediately on submission, once per account.
3. If you are in an AWS Organization, an org admin can instead call `PutUseCaseForModelAccess` once from the management account (requires `bedrock:PutUseCaseForModelAccess`); approval then extends to child accounts.

Verify:

```bash
aws bedrock list-inference-profiles --region <REGION> \
  --query "inferenceProfileSummaries[?contains(inferenceProfileId,'anthropic')].inferenceProfileId" \
  --output table
```

You should see IDs like `eu.anthropic.claude-sonnet-...`. Note the exact IDs — you need them in Step 2. **Do not copy model IDs from a blog post**; availability differs per region and per account.

## Step 2 — Create application inference profiles

These are your cost-attribution and access-control handles. One per `(team, model family)`.

```bash
export REGION=<REGION>
export TEAM=<TEAM>

# Resolve the system-defined cross-region profile ARN to copy from.
# Replace the ID with one you saw in Step 1.
SRC_SONNET=$(aws bedrock list-inference-profiles --region $REGION \
  --query "inferenceProfileSummaries[?inferenceProfileId=='<PREFIX>.anthropic.claude-sonnet-X-Y'].inferenceProfileArn" \
  --output text)

aws bedrock create-inference-profile --region $REGION \
  --inference-profile-name "claude-code-${TEAM}-sonnet" \
  --description "Claude Code - ${TEAM} - Sonnet" \
  --model-source copyFrom=$SRC_SONNET \
  --tags key=CostCenter,value=$TEAM key=Tool,value=claude-code key=ManagedBy,value=devsecops
```

Repeat for Opus if you intend to offer it. Record the returned ARNs:

```
arn:aws:bedrock:<REGION>:<ACCOUNT_ID>:application-inference-profile/xxxxxxxxxxxx
```

> **Billing:** activate `CostCenter` and `Tool` as **cost allocation tags** in the Billing console (Cost allocation tags → User-defined). They take up to 24h to appear in Cost Explorer. This is what separates Claude Code spend from power users' console spend in a shared account.

## Step 3 — Create the least-privilege invoke policy

Save as `claude-code-bedrock-invoke.json`, substituting your ARNs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvokeOnlyThroughTeamApplicationProfiles",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:<REGION>:<ACCOUNT_ID>:application-inference-profile/<SONNET_PROFILE_ID>"
      ]
    },
    {
      "Sid": "ReachBackingModelsOnlyViaThoseProfiles",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:eu-west-1::foundation-model/anthropic.*",
        "arn:aws:bedrock:eu-west-3::foundation-model/anthropic.*",
        "arn:aws:bedrock:eu-central-1::foundation-model/anthropic.*",
        "arn:aws:bedrock:eu-north-1::foundation-model/anthropic.*",
        "arn:aws:bedrock:<REGION>:<ACCOUNT_ID>:inference-profile/<PREFIX>.anthropic.*"
      ],
      "Condition": {
        "ArnLike": {
          "bedrock:InferenceProfileArn": [
            "arn:aws:bedrock:<REGION>:<ACCOUNT_ID>:application-inference-profile/*",
            "arn:aws:bedrock:<REGION>:<ACCOUNT_ID>:inference-profile/<PREFIX>.anthropic.*"
          ]
        }
      }
    },
    {
      "Sid": "ResolveProfilesAtStartup",
      "Effect": "Allow",
      "Action": [
        "bedrock:ListInferenceProfiles",
        "bedrock:GetInferenceProfile"
      ],
      "Resource": "*"
    },
    {
      "Sid": "MarketplaceSubscriptionOnlyViaBedrock",
      "Effect": "Allow",
      "Action": [
        "aws-marketplace:ViewSubscriptions",
        "aws-marketplace:Subscribe"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:CalledViaLast": "bedrock.amazonaws.com" }
      }
    }
  ]
}
```

Why each piece:

- **Statement 1** is the real boundary — invocation is only possible through your tagged profile, so every token is attributable.
- **Statement 2** is mandatory, not optional. A cross-region profile routes to foundation models in EU destination regions (`eu-west-1`, `eu-west-3`, `eu-central-1`, `eu-north-1`), and IAM evaluates authorization against the model in **each** destination region. Without it you get `AccessDenied` intermittently, only when routing lands on a region you forgot. The `bedrock:InferenceProfileArn` condition keeps that broad-looking resource list usable *only* when the call goes through your profiles.
- **Statement 3** lets Claude Code resolve an application profile ARN to its backing model so it picks the right request shape. Without `GetInferenceProfile` it still works, but pays an extra round-trip per new model.
- **Statement 4** is required by Bedrock's marketplace subscription check and is scoped so it cannot be used for anything else.

Create it:

```bash
aws iam create-policy \
  --policy-name ClaudeCodeBedrockInvoke \
  --policy-document file://claude-code-bedrock-invoke.json \
  --description "Least-privilege Bedrock invoke for Claude Code"
```

## Step 4 — Create the bearer-token deny policy

This is the one policy you also attach to **PowerUser**. It closes the short-term-API-key bypass without touching console access.

`deny-bedrock-bearer-tokens.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NoBedrockApiKeyAuth",
      "Effect": "Deny",
      "Action": "bedrock:CallWithBearerToken",
      "Resource": "*"
    },
    {
      "Sid": "NoMintingLongTermBedrockKeys",
      "Effect": "Deny",
      "Action": "iam:CreateServiceSpecificCredential",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:ServiceSpecificCredentialServiceName": "bedrock.amazonaws.com"
        }
      }
    }
  ]
}
```

```bash
aws iam create-policy \
  --policy-name DenyBedrockBearerTokens \
  --policy-document file://deny-bedrock-bearer-tokens.json
```

**What this does and does not do:**

- ❌ Blocks `AWS_BEARER_TOKEN_BEDROCK` auth (short-term *and* long-term keys) for every principal it is attached to.
- ❌ Blocks creation of long-term Bedrock API keys, which are IAM users with the over-broad `AmazonBedrockLimitedAccess` policy auto-attached.
- ✅ Leaves the Bedrock console, playground, Guardrails, and every SDK-with-SigV4 workflow working normally.

If you have AWS Organizations available, put this in an **SCP** instead so it covers principals you forget. If you don't, attach it to every permission set that reaches this account (including the admin one).

## Step 5 — Create the Claude Code permission set

```bash
INSTANCE_ARN=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text)
IDS=$(aws sso-admin list-instances --query 'Instances[0].IdentityStoreId' --output text)

PS_ARN=$(aws sso-admin create-permission-set \
  --instance-arn "$INSTANCE_ARN" \
  --name ClaudeCodeBedrock \
  --description "Claude Code via Bedrock - invoke only" \
  --session-duration PT4H \
  --query 'PermissionSet.PermissionSetArn' --output text)

aws sso-admin attach-customer-managed-policy-reference-to-permission-set \
  --instance-arn "$INSTANCE_ARN" --permission-set-arn "$PS_ARN" \
  --customer-managed-policy-reference Name=ClaudeCodeBedrockInvoke,Path=/

aws sso-admin attach-customer-managed-policy-reference-to-permission-set \
  --instance-arn "$INSTANCE_ARN" --permission-set-arn "$PS_ARN" \
  --customer-managed-policy-reference Name=DenyBedrockBearerTokens,Path=/

aws sso-admin provision-permission-set \
  --instance-arn "$INSTANCE_ARN" --permission-set-arn "$PS_ARN" \
  --target-type ALL_PROVISIONED_ACCOUNTS
```

`PT4H` is a deliberate choice: long enough to avoid re-auth fatigue mid-task, short enough that a stolen `~/.aws/sso/cache` entry is near-worthless.

## Step 6 — Attach the deny policy to PowerUser

Find the existing permission set and attach only the deny:

```bash
aws sso-admin list-permission-sets --instance-arn "$INSTANCE_ARN"
# identify the PowerUser one with describe-permission-set, then:

aws sso-admin attach-customer-managed-policy-reference-to-permission-set \
  --instance-arn "$INSTANCE_ARN" --permission-set-arn "<POWERUSER_PS_ARN>" \
  --customer-managed-policy-reference Name=DenyBedrockBearerTokens,Path=/

aws sso-admin provision-permission-set \
  --instance-arn "$INSTANCE_ARN" --permission-set-arn "<POWERUSER_PS_ARN>" \
  --target-type ALL_PROVISIONED_ACCOUNTS
```

Announce this change before rolling it out. It is invisible to 99% of power-user workflows, but someone who scripted a Bedrock key will notice.

## Step 7 — Create the group and assign

```bash
GROUP_ID=$(aws identitystore create-group --identity-store-id "$IDS" \
  --display-name claude-code-users \
  --description "Entitled to Claude Code via Bedrock" \
  --query GroupId --output text)

aws sso-admin create-account-assignment \
  --instance-arn "$INSTANCE_ARN" \
  --target-id <ACCOUNT_ID> --target-type AWS_ACCOUNT \
  --permission-set-arn "$PS_ARN" \
  --principal-type GROUP --principal-id "$GROUP_ID"
```

Sync `claude-code-users` from your IdP (Entra ID / Okta) via SCIM so that offboarding in the IdP removes Bedrock access automatically. Do not manage membership by hand.

## Step 8 — Guardrail (optional but recommended)

1. Bedrock console → **Guardrails** → create, configure filters, **publish a version**.
2. If you use cross-region inference profiles (you do), enable **Cross-Region inference** on the Guardrail.
3. Note the guardrail ID and version — they go in the developer settings file in Step 11.

## Step 9 — Logging and detection

### 9.1 CloudTrail (metadata) — always on

CloudTrail already records every `InvokeModel*` with principal, model ARN, region and time. **No prompt content.** In a shared account this is your primary audit source.

Detection rule — *Bedrock invoked outside the approved profiles* (CloudWatch Logs Insights, assuming a CloudTrail log group):

```
fields @timestamp, userIdentity.sessionContext.sessionIssuer.userName as role,
       userIdentity.principalId, requestParameters.modelId, sourceIPAddress
| filter eventSource = "bedrock.amazonaws.com"
| filter eventName like /InvokeModel/
| filter requestParameters.modelId not like /application-inference-profile/
| stats count() by role, requestParameters.modelId
```

Expected result: only console/playground traffic from PowerUser. Anything else — especially a PowerUser principal invoking with a Claude Code-shaped workload — is your signal that someone routed around the entitled path. Alert on volume, not on single events.

Also alert on:

```
eventName = "CreateServiceSpecificCredential" and requestParameters.serviceName = "bedrock.amazonaws.com"
eventName = "CallWithBearerToken"
```

### 9.2 Model invocation logging — think before enabling

```bash
aws bedrock put-model-invocation-logging-configuration --region <REGION> \
  --logging-config '{
    "cloudWatchConfig": {
      "logGroupName": "/aws/bedrock/modelinvocations",
      "roleArn": "arn:aws:iam::<ACCOUNT_ID>:role/BedrockInvocationLogging"
    },
    "textDataDeliveryEnabled": false,
    "imageDataDeliveryEnabled": false,
    "embeddingDataDeliveryEnabled": false
  }'
```

> ⚠️ **Set `textDataDeliveryEnabled: false` unless you have a specific, documented reason.**
> This setting is **account-wide**: it captures every Bedrock prompt in the account, including power users' console sessions, and Claude Code prompts contain your source code, secrets that happen to be in files, and whatever the agent read. Under GDPR that is a processing activity you must document, minimise, and set a retention period for — and a log group full of proprietary code is a higher-value target than the code repository itself.
> If you do enable it: dedicated KMS CMK, restrictive resource policy, short retention, and tell the developers in writing.

### 9.3 Cost controls

```bash
aws ce create-anomaly-monitor --anomaly-monitor '{
  "MonitorName": "bedrock-claude-code",
  "MonitorType": "DIMENSIONAL",
  "MonitorDimension": "SERVICE"
}'
```

Then a monthly AWS Budget filtered on the `Tool=claude-code` cost allocation tag, with alerts at 50/80/100%. An agent stuck in a retry loop shows up on the bill long before it shows up in any security tool.

---

# Part 2 — Developer workstation

## Step 10 — Install Claude Code

Follow the official installer for the platform: <https://code.claude.com/docs/en/overview>. Distribute via your existing package channel (Homebrew cask, MDM, internal apt repo) rather than letting each developer curl a script.

## Step 11 — AWS profile

`~/.aws/config`:

```ini
[sso-session corp]
sso_start_url = <SSO_START_URL>
sso_region = <REGION>
sso_registration_scopes = sso:account:access

[profile claude-code]
sso_session = corp
sso_account_id = <ACCOUNT_ID>
sso_role_name = ClaudeCodeBedrock
region = <REGION>
output = json
```

Ship this via configuration management. If a developer also has PowerUser, they keep their existing `[profile poweruser]` untouched — the two coexist, and Claude Code is pinned to the narrow one in Step 12.

Sign in:

```bash
aws sso login --profile claude-code
aws sts get-caller-identity --profile claude-code
```

The ARN should contain `AWSReservedSSO_ClaudeCodeBedrock`.

> Note: `sso_region` is the region of your IAM Identity Center instance. It does not have to match your Bedrock region, and Claude Code requests role credentials from the region named in the profile.

## Step 12 — Claude Code settings

`~/.claude/settings.json`:

```json
{
  "awsAuthRefresh": "aws sso login --profile claude-code",
  "env": {
    "CLAUDE_CODE_USE_BEDROCK": "1",
    "AWS_PROFILE": "claude-code",
    "AWS_REGION": "<REGION>",
    "ANTHROPIC_MODEL": "arn:aws:bedrock:<REGION>:<ACCOUNT_ID>:application-inference-profile/<SONNET_PROFILE_ID>",
    "ANTHROPIC_CUSTOM_HEADERS": "X-Amzn-Bedrock-GuardrailIdentifier: <GUARDRAIL_ID>\nX-Amzn-Bedrock-GuardrailVersion: 1"
  }
}
```

Notes:

- **`AWS_PROFILE` lives in the settings file, not the shell.** Exporting it in `.zshrc` leaks it to every other process and makes it trivial for a developer to point Claude Code at their PowerUser profile without noticing.
- **`ANTHROPIC_MODEL` set to the profile ARN is what actually enforces attribution.** Without it, Claude Code resolves the `sonnet`/`opus` aliases to its own built-in defaults, which your policy denies — and unpinned deployments now default to an Opus-class primary model, billed at the Opus rate.
- **`awsAuthRefresh`** re-runs SSO login when credentials expire, then retries. Claude Code first makes an STS `GetCallerIdentity` call to confirm expiry, so it won't spawn browser tabs unnecessarily.
- To offer more than one model, create a profile per model and map them with `modelOverrides` + `availableModels` in the same file rather than letting developers pick arbitrary model IDs.

Distribute this as a **managed settings file** (enterprise-enforced layer, path per OS in the [settings docs](https://code.claude.com/docs/en/settings)) so developers cannot edit the `env` block. A user-level `~/.claude/settings.json` is a starting point, not a control.

## Step 13 — First run and verification

```bash
aws sso login --profile claude-code
claude
```

Inside the session, run `/status`. You should see provider `Amazon Bedrock`, your region, and the resolved model. Then check the account side:

```bash
aws bedrock list-inference-profiles --region <REGION> --profile claude-code
```

## Step 14 — Prove the boundary holds

Run all four. A control you have not tested is a control you do not have.

| # | Test | Command | Expected |
|---|---|---|---|
| 1 | Entitled path works | `claude -p "say hello"` | Response returned |
| 2 | No lateral movement | `aws s3 ls --profile claude-code` | `AccessDenied` |
| 3 | No direct model access | `aws bedrock-runtime invoke-model --profile claude-code --region <REGION> --model-id <PREFIX>.anthropic.claude-sonnet-X-Y --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}' --cli-binary-format raw-in-base64-out /tmp/o.json` | `AccessDenied` — bypassing the app profile is blocked |
| 4 | Bearer-token bypass closed | Mint a short-term key in the console as a **power user**, then `AWS_BEARER_TOKEN_BEDROCK=... claude` | Denied |

Test 3 is the one that tells you the `bedrock:InferenceProfileArn` condition is wired correctly. Test 4 is the one that tells you constraint #3 is actually satisfied.

Then confirm attribution: after a day of use, Cost Explorer filtered on `Tool=claude-code` should show non-zero spend, and `CostCenter` should split it by team.

---

# Part 3 — Operations

## Offboarding

Remove the user from `claude-code-users` in the IdP. SCIM removes the account assignment; the existing session dies within 4 hours. No key rotation, no secret sweep — this is the entire point of not using API keys.

## Adding a team

1. Create `claude-code-<TEAM>-sonnet` application inference profile with that team's tags.
2. Add its ARN to `ClaudeCodeBedrockInvoke` statement 1.
3. Either create a per-team permission set, or reuse one and vary `ANTHROPIC_MODEL` per team via managed settings.

## Incident: suspected credential misuse

1. Disable the account assignment for the affected principal (`delete-account-assignment`) — immediate.
2. Pull CloudTrail for `bedrock.amazonaws.com` filtered on the principal ID.
3. If prompt content matters to the investigation and invocation logging was off, you have metadata only. Decide that trade-off now, not during the incident.

## Review cadence

- **Monthly:** review `claude-code-users` membership against the IdP source of truth.
- **Monthly:** run the Step 9.1 detection query; a rising count means the entitled path is too painful and people are routing around it. Fix the path, not the people.
- **Per Claude Code release:** re-check pinned model ARNs; Claude Code prompts to update a pin when a newer default becomes available, but pins pointing at application inference profile ARNs are skipped as administrator-managed.

---

# Appendix A — Rejected options and why

| Option | Verdict |
|---|---|
| IAM user + long-lived access keys | Never. Non-attributable, non-rotating, ends up in dotfiles and Git. |
| Long-term Bedrock API key (`AWS_BEARER_TOKEN_BEDROCK`) | Never for developers. Creates an IAM user with `AmazonBedrockLimitedAccess` auto-attached — which despite the name covers most of the Bedrock service, including creating and deleting guardrails. No MFA, no IdP-tied expiry, no clean per-user revocation. |
| Short-term Bedrock API key | Denied explicitly in Step 4. Any console session can mint one, it bypasses your permission set, and nothing is logged at creation time. |
| Stripping `bedrock:*` from PowerUser | Rejected — it breaks the console for power users, which constraint #3 forbids. Their Bedrock spend is instead made visible by the absence of a `claude-code` tag. |
| Region-deny SCP for Bedrock | Handle with care. A region-deny SCP breaks cross-region inference unless you exempt destination regions with a `bedrock:InferenceProfileArn` condition. Test it in a sandbox first. |
| Trusting `ANTHROPIC_MODEL` in a user-writable settings file | Insufficient alone. It is a routing convenience; the IAM policy in Step 3 is the actual boundary. |

# Appendix B — Troubleshooting

| Symptom | Cause |
|---|---|
| `AccessDenied` on some requests only | Missing foundation-model permission in one cross-region destination region. Add it to statement 2. |
| `on-demand throughput isn't supported` | You passed a bare foundation model ID. Use an inference profile ID or ARN. |
| Repeated browser tabs during SSO | A TLS-inspecting proxy interrupts the SSO flow and `awsAuthRefresh` loops. Remove `awsAuthRefresh` and have developers run `aws sso login` manually. |
| `unable to get local issuer certificate` | Corporate root CA not visible. Put it in the OS trust store or `NODE_EXTRA_CA_CERTS`, and update Claude Code — older versions only applied CA config to proxied requests. |
| `Session token not found or invalid` | Identity Center instance region differs from the Bedrock region on an older Claude Code build. Upgrade. |
| `/logout` does nothing | Expected. On Bedrock, authentication is AWS credentials; revoke in Identity Center. |
| WebSearch tool missing | Expected. WebSearch is not available on Bedrock. |

# References

- Claude Code on Amazon Bedrock — <https://code.claude.com/docs/en/amazon-bedrock>
- Claude Code settings — <https://code.claude.com/docs/en/settings>
- Bedrock API key permissions (`bedrock:CallWithBearerToken`, `bedrock:bearerTokenType`) — <https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-permissions.html>
- Inference profile prerequisites and `bedrock:InferenceProfileArn` — <https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-prereq.html>
- Geographic cross-region inference and SCP interaction — <https://docs.aws.amazon.com/bedrock/latest/userguide/geographic-cross-region-inference.html>
- Bedrock security and IAM — <https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html>
