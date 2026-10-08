# fortinet-fortiaigate release notes

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
