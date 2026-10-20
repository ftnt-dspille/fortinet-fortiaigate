# Fortinet FortiAIGate - FortiSOAR connector

A FortiSOAR connector for FortiAIGate, Fortinet's inline AI gateway. It works
through [pyfortiaigate](https://pypi.org/project/pyfortiaigate/) (pip-installed when
the connector is installed; needs Python 3.10 or newer), which talks to the
gateway's admin console JSON API (session cookie plus per-mutation CSRF token) and
to its OpenAI-compatible data plane.

Operations: list workspaces (org-wide, or the login's own), list / get / create /
update / rotate / renew / revoke virtual keys, data-plane key validation
(`check_key`), guarded chat completions (`chat_completion`), guardrail listing and
scanning (`test_guardrail` - scan arbitrary text, no LLM involved), policies, provider
health (`list_ai_providers`), workspace budgets, the admin audit log (cursor-paged,
with filter options), **Get Blocked Traffic** (the requests the gateway blocked, with
the prompt, the detectors that fired and the sending key), and Execute API Request:
any management API endpoint (GET, POST, PUT, PATCH, DELETE) called with the
configured login. A full URL is refused so the credentials never leave the
configured server.

A login can be an organization administrator (every workspace) or a workspace admin
(its own workspace). The connector detects which and routes each call; set
**Workspace** for a login that belongs to several workspaces. A workspace **member**
is refused at the health check: FortiAIGate answers a member 403 ("Workspace
administrator access required") on keys, guardrails, policies, detectors and logs.

Dynamic dropdowns: wherever a parameter takes an identifier or model name
(workspace, key, policy, guardrail, detector, model), the step editor fetches live
options through the connector (`apiOperation`) so users pick from names; the
connector turns the picked name into the id the API needs when the action runs. A
playbook can pass a name or a bare id. The `get_*_options` operations that feed them
are hidden from the palette but callable like any other step.

## Scheduled ingestion of blocked AI requests

The connector is a scheduled ingestion source for the **Alerts** module. Each request
the gateway blocked becomes one alert, keyed on the request's uuid, so a window that
is read twice updates its alerts instead of duplicating them.

The prebuilt collection `Sample - Fortinet FortiAIGate - 1.6.0` has three workflows,
the same shape as the FortiSIEM v2 connector's ingestion chain:

- `>> FortiAIGate > Init Macros` creates the per-configuration last-pull-time macro.
- `> FortiAIGate > Fetch` reads the macro, calls **Get Blocked Traffic** since it, and
  returns the records. The first run (no watermark yet) reads the **Initial Backfill
  Range**. **Maximum Requests Per Run** caps a run; the cap keeps the newest requests,
  so a run that reaches it does not read the older requests of its window.
- `FortiAIGate > Ingest` is the wizard's entry point. It shows the Data Mapping
  preview, creates the alerts (`Create Record`) and then moves the watermark, so a
  failed run reads its window again. The window ends 60 seconds behind the clock,
  because a traffic log row lands a few seconds after its request.

Alert mapping (`Create Record`, upserted on `sourceId`):

| Alert field | Value |
|---|---|
| `sourceId` | the blocked request's uuid |
| `source` | `Fortinet FortiAIGate` |
| `name` | `FortiAIGate blocked a prompt from <key name>: <reason>` |
| `description` | the prompt, then the detectors that fired (name, side, details) |
| `severity` | `High` (a picklist value, `"Severity" \| picklist("High")`) |
| `alertDetectionDate` | the request time, epoch seconds |
| `sourcedata` | the whole blocked request as JSON (`vars.item \| toJSON`) |
| `owners` | the connector configuration's teams (`ownerTeams`); none for a shared configuration |

No other alert fields are set; everything the gateway recorded is in `sourcedata`.

Ownership: Get Blocked Traffic reads its own configuration's teams through FortiSOAR
(`config_id`) and returns them on each record as `ownerTeams`. A configuration Private
to a team therefore ingests alerts that team owns, whoever or whatever runs the
schedule. Without it the alerts went to the playbook's default team, which a student
on a Private configuration cannot read. The lookup happens in the connector, not the
playbook, because the configuration API also returns the encrypted password.

Ingestion needs the connector's sample collection installed and enabled in the Data
Ingestion wizard, against a FortiSOAR appliance that runs this connector version.

Key lifecycle details:

- rotate -> gateway invalidates the old secret, issues a new one. The response is
  the key record plus its new secret as `secretKey`. The gateway only rotates a key
  that is still active: an expired, revoked or suspended key answers "cannot be
  rotated: mint a new key instead".
- renew -> **Renew Virtual Key** gives the same key a new secret: it rotates an
  active key, and extends an expired one first (an expired key is active again once
  its expiry is in the future), returning `secretKey`. The key keeps its id, name,
  limits, policies and model access. A revoked or suspended key is refused.
- revoke -> sends a reason (the gateway requires one); set it with the optional
  Reason parameter. Pass the key by name or id.
- create -> the gateway returns the secret exactly once (`secretKey`); the management
  API never shows it again - store it immediately.
- update virtual key -> merge-update: the API replaces the whole record, so the
  library reads the current record and resends it plus your changes.

## Sample playbooks: renew keys before they expire, and onboard new ones

`Heal Expired FortiAIGate Key in Vault` keeps an application's key working.
Give it the KV v2 path of the secret (`secret_path`, and `key_field` when the key is
not stored under `api_key`). It reads the key, tests it against the data plane, and
when the key no longer works renews it (same key, new secret), writes the new secret
to the same path as a new Vault version with every other field of the secret kept,
and verifies it. A working key is left alone, and a revoked or suspended key stops
the run with a message so a person decides. It needs the `hashicorp-vault-kv`
connector with a write-capable token, and returns `rotation_result`, `rotated`,
`key_id` and `key_method`. Schedule it, or call it once per secret from a parent
playbook.

### Vault lifecycle playbooks (1.6.1 - 1.6.13 hardening)

These need `hashicorp-vault-kv` 1.2.1 or later. Each FortiAIGate key is linked to
the Vault secret that holds it by a custom metadata tag on that secret,
`faig_key_id=<key uuid>`. Vault cannot search, so the renewal lists a folder and
reads each secret's metadata; it never reads a secret value.

- **Renew Expiring FortiAIGate Keys in Vault** (schedule it, for example every
  15 minutes): lists the keys that expire within `within_days` (default 2) or
  already have, finds the tagged secrets under `secret_folder` (default `lab`),
  and renews each key that exactly one secret is tagged with, through the child
  playbook. A key no secret is tagged with is left to expire (no app uses it); a
  key tagged on two secrets is not touched and reported in `conflicts`.
  `extend_days` (default 7) must be more than `within_days`, or every run would
  renew the same keys again; the playbook refuses that.
- **Renew FortiAIGate Key in Vault** (the child): renews one key, PATCHes only
  `api_key` in its secret, stamps `faig_rotated_at` and `faig_expires_at`, and
  verifies the new secret. It always ends on a result: `renewed`,
  `renew_failed` (a revoked key, say) or `write_failed`. After a failed write the
  new secret is stored nowhere; fix Vault and run it again.
- **Onboard FortiAIGate Key to Vault** (API endpoint
  `POST /api/triggers/1/fortiaigate/onboard-key`, token authentication): creates a
  key for an app and stores it, tagged, in a new Vault secret. Body:
  `secret_path` (required), `key_name` (default: the path), `workspace`,
  `providers` (default `openai`), `expires_in_days` (default 7), `fields` (extra
  secret fields such as `base_url`). An existing secret is never overwritten
  (`path_in_use`), and the key is revoked if the Vault write fails. The trigger
  returns a `task_id`; the last step returns `key_name`, `secret_path`,
  `key_id`, `expires_at` and `outcome`.
- **Revoke FortiAIGate Key on Guardrail Block** (API endpoint
  `POST /api/triggers/1/fortiaigate/guardrail-block`, token authentication):
  reacts to a FortiAIGate DLP, ATLAS or detector block. Body: `key_id`
  (required), `workspace_id`, `policy`, `request_id`, `secret_folder` (default
  `lab`), `extend_days` (default 7), `max_peers` (default 25). Revokes the bad
  key FIRST (attacker loses access while the run finishes the rest), clears the
  Vault secret the key was in (`api_key=REVOKED`), stamps `faig_revoked_at`,
  `faig_revoked_policy` and `faig_revoked_request` on it, then rotates every
  peer secret under `secret_folder` tagged with the same `faig_workspace_id`
  through the child renewal. Over `max_peers` the run flags only (contains a
  loud blast radius). Outcomes: `revoked_and_rotated`, `revoked_no_peers`,
  `revoked_orphan`, `too_many_peers`, `conflict`, `bad_request`. Needs
  `faig_workspace_id` on each tagged secret: onboarding stamps it, and
  `scripts/backfill_workspace_tag.py` fills in secrets created before 1.6.4.

What has to be in place:

- A Vault policy on the folder for the token in the default `hashicorp-vault-kv`
  configuration - find and update, never read:

  ```hcl
  path "secret/metadata/apps/*" { capabilities = ["read", "list", "patch"] }
  path "secret/metadata/apps"   { capabilities = ["list"] }
  path "secret/data/apps/*"     { capabilities = ["create", "patch"] }
  ```

  (`create` is for onboarding only.) Use a periodic token or AppRole: if the
  token expires, every run fails.
- A FortiAIGate login in the default configuration that can list keys, update
  their expiry and rotate them, in every workspace the folder's apps use (an
  organization administrator, or a workspace administrator per workspace). To
  onboard, the login must be a member of the target workspace; it becomes the
  key's owner.
- Every secret tagged with `faig_key_id`. Onboarding does this; tag secrets
  that already exist once, as an administrator (it is the only step that has to
  read a secret).
- Only SOAR and Vault administrators may write metadata under the folder. The
  `faig_key_id` tag is the only link from a key to its secret, so whoever can
  tag a secret can have another key's new secret written into it. App teams
  need read on their own secret's data, nothing on metadata.
- Who may call the onboarding route: it is token-authenticated, so it runs as
  the calling FortiSOAR user or API key. Give that permission to the systems
  that onboard apps (a pipeline, an ITSM integration) only. The playbook
  refuses a `secret_path` containing `..`, and the Vault policy keeps writes
  inside the folder.
- Apps that pick up a changed secret by themselves (a Vault Agent template, a
  watcher). The old secret stops working the moment the key is rotated.

**Debug mode is on** in all the sample playbooks. FortiSOAR keeps a run's step
outputs only for a playbook in debug mode, and without them an API caller cannot
read what the onboarding returned. The cost: debug also keeps every step's
output, and the Create and Renew steps return the new secret, so it sits in
plaintext in the run history until the key is rotated again or the logs are
purged. Restrict who can read playbook execution logs, and keep log retention
short.

## Tests

```
python -m venv .venv && .venv/bin/pip install -r tests/requirements.txt
.venv/bin/pip install -e /path/to/pyfortiaigate   # until pyfortiaigate 0.4.0 is on PyPI
.venv/bin/pytest tests/test_offline.py            # loopback fake gateway, no network
cp tests/.env.example tests/.env                  # fill in, then
.venv/bin/pytest tests/test_live.py -m live       # read-only against a real gateway
FAIG_ALLOW_MUTATE=true .venv/bin/pytest tests/test_live.py -m mutate   # disposable key
```

The playbooks are compiled from `playbooks/playbooks.yaml` with
`python playbooks/build.py` (it calls the `fsrpb` compiler of the FSR playbook
framework). Check the ingestion collection with `fsrpb validate-ingestion
playbooks/playbooks.json`.

## Packaging

`scripts/package.sh` builds `dist/fortinet-fortiaigate-<version>.tgz` (single
top-level `fortinet-fortiaigate/` directory - what FortiSOAR's connector import
expects). Prefers git-tracked files, falls back to the working tree excluding
tests / scripts / dist / caches.
