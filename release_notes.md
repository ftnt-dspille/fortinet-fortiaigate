# fortinet-fortiaigate release notes

## 1.6.6

More hardening on the revocation playbook:

- `extend_days` and `max_peers` from the request body are clamped to safe
  ranges (`1-30` days, `1-50` peers), so a caller cannot bypass the fan-out
  cap or push the whole fleet's expiry out past the policy.
- `secret_folder` is rejected if it contains a `.` or `..` segment, so a
  caller cannot escape the configured app folder when searching for peers.
- The verification of a request as a real FortiAIGate block (lookup by
  `request_id` in the traffic logs) is left as a documented future
  enhancement; for now the route's SOAR token is the control, so give it
  only to systems authorized to revoke a key.

## 1.6.5

Security fixes to the new revocation playbook from 1.6.4:

- The workspace used for peer rotation now comes from the bad secret's own
  Vault metadata (set by onboarding, trusted). The `workspace_id` in the
  caller's request body is ignored - a caller could otherwise point peer
  rotation at a different workspace.
- An empty workspace never fans out. If the bad secret has no
  `faig_workspace_id` tag, the run ends on `revoked_no_peers` instead of
  looking for secrets tagged with "".
- A failed `revoke_virtual_key` is now a terminal `revoke_failed`, not a
  success. On the error path the Vault secret is NOT cleared (the app would
  otherwise fail-closed while the attacker's key is still live) and no peers
  are rotated. A person is paged.
- Metadata patches skip empty values so Vault's non-empty-value check
  doesn't fail the stamp (`faig_revoked_request` is optional).

## 1.6.4

- New sample playbook **Revoke FortiAIGate Key on Guardrail Block**: an
  `api_endpoint` playbook that revokes the virtual key named in a FortiAIGate
  guardrail-block event, clears its Vault secret with `api_key=REVOKED` and
  stamps `faig_revoked_at` / `faig_revoked_policy` / `faig_revoked_request`,
  then rotates every peer secret tagged with the same `faig_workspace_id` so
  the blast radius is contained. Peers are rotated through the existing child
  **Renew FortiAIGate Key in Vault**, so each keeps its key id, policies,
  limits and model access and only the Vault secret's `api_key` field
  changes. Outcomes: `revoked_and_rotated`, `revoked_no_peers`,
  `revoked_orphan` (no tagged secret), `too_many_peers` (over `max_peers`),
  `conflict` (two secrets tagged to the same bad key) and `bad_request`.
- **Onboard FortiAIGate Key to Vault** also stamps `faig_workspace_id` on the
  new secret, from the key's resolved workspace id. The renewal playbooks are
  unaffected (they match on `faig_key_id`), but revocation needs this join
  column. A one-time backfill script (`scripts/backfill_workspace_tag.py`)
  adds it to pre-1.6.4 secrets.

## 1.6.3

- **Onboard FortiAIGate Key to Vault** checks the secret path before any Vault
  call, so a path with a `.` or `..` segment returns `secret_path_not_allowed` to
  the caller instead of failing the run (`hashicorp-vault-kv` 1.2.1 refuses such
  a path itself). Sample playbooks are built against `hashicorp-vault-kv` 1.2.1.

## 1.6.2

- An id of `.` or `..` (or an empty one) is refused before any API call. URL
  encoding leaves dots alone, so in 1.6.1 an id of exactly `..` could still climb
  one level of the API path.

## 1.6.1

- Every id put into an API path (key, workspace, policy, guardrail, detector) is
  URL-encoded. Ids now reach paths from playbook input - a Vault metadata tag, an
  onboarding API body - and a value such as `../../admin/...` could otherwise
  steer the connector's session to another route.
- **Onboard FortiAIGate Key to Vault** refuses a `secret_path` containing `..`
  (`secret_path_not_allowed`).
- README: who may write the Vault tags, and who may call the onboarding route.

## 1.6.0

- New operation **List Expiring Virtual Keys**: keys that expire within
  **Within (Days)** (default 7), soonest first, and by default the ones already
  expired. Keys with no expiry and revoked or suspended keys are never listed.
- **Renew Virtual Key** now also moves out an expiry that would come within
  **Extend By (Days)**, so a key renewed before it expires no longer expires a
  few days later anyway. An expiry is never shortened; a key with no expiry is
  only rotated. Output adds `old_expires_at`.
- **Create Virtual Key** takes **Providers** (FortiAIGate 8.0.2 refuses a key
  with no model access) and **Expires In (Days)**, and returns the secret as
  `new_secret` as well as the gateway's own field.
- Fixed: **Create Virtual Key** failed on 8.0.2 for an organization administrator
  with HTTP 404 "the key owner is not a member of this workspace", even for a
  member. Keys are now always created through the workspace route.
- New sample playbooks **Renew Expiring FortiAIGate Keys in Vault**, **Renew
  FortiAIGate Key in Vault** and **Onboard FortiAIGate Key to Vault** (an API
  endpoint): keys are linked to their Vault secrets by a `faig_key_id` metadata
  tag, renewed before they expire, and written back without reading any secret.
  They need `hashicorp-vault-kv` 1.2.0. They replace the sample playbook **Heal
  Expired FortiAIGate Key in Vault**, which is removed: the renewal covers expired
  keys too, and Heal read the secret, which the renewal never does. All sample
  playbooks run in debug mode so
  an API caller can read the results; see the README for what that keeps in the
  run history.

## 1.5.1

- **Renew Virtual Key** never leaves an expired key's old secret working. Extending the
  expiry reactivates the old secret until the rotate replaces it; if the rotate fails, the
  original expiry is put back (the key is expired again) and, if that fails too, the key is
  revoked. **Extend By (Days)** must be between 0 and 3650.

## 1.5.0

- **Renew Virtual Key** replaces **Replace Virtual Key**, and no longer creates a new key.
  FortiAIGate only rotates an active key, but an expired key becomes active again when its
  expiry moves into the future. So an expired key is extended (**Extend By (Days)**,
  default 30) and then rotated; an active key is rotated. The key keeps its id, name,
  limits, policies and model access, so nothing has to be copied and nothing is left
  behind. A revoked or suspended key is refused and left untouched. The New Key Name,
  Revoke Old Key, Allow Replacing a Revoked Key and Allow Replacement Without Model Access
  Limits options are gone. A playbook that calls `replace_virtual_key` must switch to
  `renew_virtual_key`; its output has `key_id` in place of `old_key_id`/`new_key_id`.
- The sample playbook **Heal Expired FortiAIGate Key in Vault** renews the key and writes
  the new secret back to Vault as before; it returns `key_id` instead of `new_key_id`, and
  `key_method` is `rotated` or `extended_and_rotated`. It also takes `secret_path` and
  `key_field` as top-level variables, so an API trigger (which does not fill the playbook
  parameters) no longer falls back to the default path.
- Fixed: **Update Virtual Key** failed on 8.0.2 with HTTP 422 for every key. It resent the
  whole record, read-only fields (`status`, `updatedAt`, ...) and policies as objects
  included. It now sends only the writable fields, and keeps organization-assigned
  policies when **Policy IDs** replaces the key's own (leaving one out reads as detaching
  it, which only an organization administrator may do).

## 1.4.0

- **Works with a workspace login.** The connector reads the login's role (`GET /api/v1/user`).
  An organization administrator keeps the `/api/v1/admin` API and sees every workspace. Any
  other login (a workspace admin or member) is detected automatically and works in its own
  workspace through `/api/v1/workspaces/<id>`. That covers virtual keys (list, get, create,
  update, rotate, replace, revoke), guardrails and guardrail tests, policies, detectors,
  budget and audit logs. Before 1.4.0 such a login could only list its workspaces; every
  other action failed with HTTP 403 "Organization-level access required".
- New optional configuration field **Workspace** (name or id). A login with one workspace
  uses it without being told. A login with several uses the configured one, or the
  workspace an action names. The health check fails if the login is not a member of the
  configured workspace.
- **Create Virtual Key** and **Get Workspace Budget** no longer require a workspace for a
  workspace login.
- Actions that need an organization administrator (List AI Providers, admin paths in
  Execute API Request) now say so and name the login, instead of a bare 403.
- One action logs in and looks up the role and workspace once, not once for the dropdown
  names and again for the call.

## 1.3.4

- **Replace Virtual Key** now fails closed. A revoked key is shut off on purpose, so it is
  not replaced unless **Allow Replacing a Revoked Key** is on. A key with model groups or
  provider access is not replaced unless **Allow Replacement Without Model Access Limits**
  is on, because those limits are not copied and the new key could reach more than the old
  one; nothing is created in either case. The sample playbook leaves both off, so it stops
  with a clear message for such keys.
- A key secret that is not `faig_<32 hex>_...` is rejected instead of being turned into an id.

## 1.3.3

- New operation **Replace Virtual Key**: FortiAIGate only rotates a key that is still
  active; an expired, revoked or suspended key "cannot be rotated: mint a new key
  instead". Replace Virtual Key rotates an active key in place and otherwise creates a
  new key in the same workspace with the same name, limits and policies (a suspended
  key is revoked afterwards), and returns `new_secret`. Pass the key (name or id) or its
  secret.
- The sample playbook **Heal Expired FortiAIGate Key in Vault** now does the real job:
  when the key stored in Vault has expired, been revoked or been suspended, it issues
  a replacement, writes it to the same Vault path as a new version, keeping every other
  field of the secret, and verifies the new key. It takes `secret_path` and an optional
  `key_field`, and reports `rotated`, `new_key_id` and `key_method`.
- When several keys share a name (a renewed key keeps its name), a key dropdown value
  resolves to the single active one.

## 1.3.2

- Fixed: **Revoke Virtual Key** failed on FortiAIGate 8.0.2 with "expected required
  property reason to be present". It now sends a reason, set with the new optional
  **Reason** parameter (default "Revoked from FortiSOAR").

## 1.3.1

- Fixed: the workspace, key, policy, guardrail and detector dropdowns showed
  "[object Object]" for every entry. They now list plain names. A picked name
  is resolved to its id when the action runs (a bare id still works, so existing
  playbooks keep working, and a name shared by two items is an error that lists
  the ids).

## 1.3.0

- New operation **Execute API Request**: call any FortiAIGate management API
  endpoint (GET, POST, PUT, PATCH, DELETE) with the configured login, session
  and CSRF handling. A full URL, a `//host` start, a `..` segment or a
  backslash is refused, so the credentials only go to the configured server.

## 1.2.1

- House style: single-dash conventions across prose, code banners, and the
  bundled sample playbook; example env and docs scrubbed of lab specifics.
  No functional changes.

## 1.2.0

- Dynamic dropdowns (apiOperation) so step editors pick from live values
  instead of typing ids: workspaces (creation membership first, then
  org-wide), virtual keys (name + status), policies, guardrails, detectors
  (built-in slug ids first, then workspace custom uuids) and chat completion
  models (public names from the organization's model groups).
- The populating operations (get_*_options) are hidden from the playbook
  palette (visible: false) and usable anywhere as regular steps too.
- test_guardrail detector_ids and update_virtual_key policy_ids are now
  multiselects; the handlers accept either selected lists or legacy
  comma-separated strings.

## 1.1.0

- Governed AI usage: chat_completion runs OpenAI-compatible completions
  through the data plane with the key's guardrails enforced; returns the
  assistant content, finish reason and token usage.
- Guardrail scanning: test_guardrail answers "would these detectors fire?"
  for arbitrary text (no LLM involved); take detector ids directly or from a
  guardrail. list_guardrails and get_guardrail expose the named detector
  sets.
- Policy visibility: list_policies / get_policy (status, guardrail
  assignments, provider access, pending changes); update_virtual_key can
  replace a key's attached policy_ids.
- Audit: list_audit_logs (paginated, newest first; total/hasNext) and
  get_audit_log_filter_options for dashboards and picklists.
- Provider health: list_ai_providers (platform, model/key counts).
- Workspace API: get_workspace_budget (spend vs budget and cycle);
  list_my_workspaces (key creation requires the key owner to be a workspace
  member - me/workspaces is the authoritative membership list).
- Live-validated endpoint shapes on FortiAIGate 8.0.2: policies, guardrails
  + test, providers, budget, audit pagination, and chat completions
  (max_tokens accepted, standard OpenAI response).

## 1.0.1

- rotate_virtual_key accepts the key secret (api_key) instead of the key id -
  the connector derives the record id from the secret, which embeds it.
- Mutations always send a JSON body: the management API rejects bodiless
  POSTs with "request body is required".
- Sample playbook "Heal Expired FortiAIGate Key in Vault" (playbooks/) - reads
  the api_key from a hashicorp-vault-kv secret, validates it against the
  data plane, rotates it when invalid, writes the new secret to Vault as a
  new KV version (preserving the other fields) and verifies it. Instance-
  portable: no code_snippet steps (the compiler pins the code-snippet config
  UUID of the instance its catalog was warmed from).

## 1.0.0

- Initial release: list workspaces, list / get / create / update / rotate /
  revoke virtual keys, data-plane key validation (`check_key`).
- Typed management client with session + per-mutation CSRF handling and
  automatic re-login on session expiry.
- Offline test suite against a loopback fake gateway; opt-in live tests
  (read-only by default, mutating tests via FAIG_ALLOW_MUTATE=true).
