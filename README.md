# Fortinet FortiAIGate - FortiSOAR connector

A FortiSOAR connector for FortiAIGate, Fortinet's inline AI gateway.
It manages the gateway's *virtual keys* - the `faig_...` data-plane API
secrets client applications present to the OpenAI-compatible endpoint -
through the admin console's JSON management API (session cookie plus
per-mutation CSRF token).

Operations: list workspaces (org-wide and the admin's own memberships),
list / get / create / update / rotate / revoke virtual keys, data-plane key
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
from names while playbooks receive stable ids. The `get_*_options`
operations that feed them are hidden from the palette but callable like any
other step.

Key lifecycle details:

- rotate -> gateway invalidates the old secret, issues a new one; the
  response's secret is extracted into `new_secret` when present.
- create -> the gateway returns the secret exactly once (`secretKey`);
  the management API never shows it again - store it immediately.
- update virtual key -> merge-update: the API replaces the whole record,
  so the connector reads the current record and resends it plus your
  changes.

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
