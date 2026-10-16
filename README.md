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
or member (its own workspace). The connector detects which and routes each call;
set **Workspace** for a login that belongs to several workspaces.

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

No other alert fields are set; everything the gateway recorded is in `sourcedata`.

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

## Sample playbook: heal an expired key stored in Vault

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
