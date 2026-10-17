# Fortinet FortiAIGate - FortiSOAR connector

A FortiSOAR connector for FortiAIGate, Fortinet's inline AI gateway.
It manages the gateway's *virtual keys* - the `faig_...` data-plane API
secrets client applications present to the OpenAI-compatible endpoint -
through the admin console's JSON management API (session cookie plus
per-mutation CSRF token).

Operations: list workspaces (org-wide and the admin's own memberships),
list / get / create / update / rotate / renew / revoke virtual keys, data-plane key
validation (`check_key`), guarded chat completions (`chat_completion`),
guardrail listing and scanning (`test_guardrail` - scan arbitrary text, no
LLM involved), policies (list / get, plus attaching policy ids to keys),
provider health (`list_ai_providers`), workspace budgets, and the admin
audit log (paginated, with filter options), and execute API request: any
management API endpoint (GET, POST, PUT, PATCH, DELETE) called with the
configured login; a full URL is refused so the credentials never leave the
configured server.

Dynamic dropdowns: wherever a parameter takes an identifier or model name
(workspace, key, policy, guardrail, detector, model), the step editor
fetches live options through the connector (`apiOperation`) so users pick
from names; the connector turns the picked name into the id the API needs when
the action runs. A playbook can pass a name or a bare id. The `get_*_options`
operations that feed them are hidden from the palette but callable like any
other step.

Key lifecycle details:

- rotate -> gateway invalidates the old secret, issues a new one; the
  response's secret is extracted into `new_secret` when present. The gateway
  only rotates a key that is still active: an expired, revoked or suspended
  key answers "cannot be rotated: mint a new key instead".
- renew -> **Renew Virtual Key** gives the same key a new secret: it
  rotates an active key, and extends an expired one first (an expired key is
  active again once its expiry is in the future), returning `new_secret`.
  The key keeps its id, name, limits, policies and model access. A revoked
  or suspended key is refused.
- revoke -> sends a reason (the gateway requires one); set it with the
  optional Reason parameter.
- create -> the gateway returns the secret exactly once (`secretKey`);
  the management API never shows it again - store it immediately.
- update virtual key -> merge-update: the API replaces the whole record,
  so the connector reads the current record and resends it plus your
  changes.

## Sample playbooks: renew keys before they expire, and onboard new ones

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
pytest tests/test_offline.py       # loopback fake gateway, no network
cp tests/.env.example tests/.env   # fill in, then
pytest tests/test_live.py -m live  # read-only against a real gateway
FAIG_ALLOW_MUTATE=true pytest tests/test_live.py -m mutate   # disposable key
```

## Packaging

`scripts/package.sh` builds `dist/fortinet-fortiaigate-<version>.tgz`
(single top-level `fortinet-fortiaigate/` directory - what FortiSOAR's
connector import expects). Prefers git-tracked files, falls back to the
working tree excluding tests / scripts / dist / caches.
