"""Operation handlers for the FortiAIGate connector. Each takes
``(config, params)`` and returns a JSON-serializable result."""

from __future__ import annotations

import re
from typing import Optional

from connectors.core.connector import ConnectorError

from .connections import FaigClient, json_object, key_id_from_secret

operations = {}


def _client(config):
    return FaigClient(
        server=config['server'],
        username=config['username'],
        password=config['password'],
        verify_ssl=config.get('verify_ssl', True),
        data_plane_base=config.get('data_plane_base') or None,
        timeout=config.get('timeout') or 30,
    )


# The platform draws a dropdown from a plain list of strings (a {title, value} object
# renders as "[object Object]") and hands the action exactly the text that was picked.
# So the id-backed dropdowns list names, which FortiAIGate keeps unique, and
# resolve_names() turns a picked name into its id before an action runs. A bare id
# passes through untouched, so playbooks that supply one keep working.
_UUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def _names(rows):
    """The distinct names of `rows`, in order, for a dropdown."""
    return list(dict.fromkeys(row[0] for row in rows))


def _workspace_rows(client):
    return [(w.get('_workspaceName') or w.get('workspaceName'), w.get('_id') or w.get('id'))
            for w in (client.list_my_workspaces() or client.list_workspaces())]


def _key_rows(client):
    # (name, id, active): names are not unique, and a renewed key reuses its name
    return [(k.get('keyName'), k.get('id'), k.get('status', 'active') == 'active')
            for k in client.list_virtual_keys()]


def _policy_rows(client):
    return [(p.get('name'), p.get('id')) for p in client.list_policies()]


def _guardrail_rows(client):
    return [(g.get('name'), g.get('id')) for g in client.list_guardrails()]


def _detector_rows(client):
    return ([(d['_name'], d['_id']) for d in client.list_builtin_detectors()]
            + [(d['_name'], d['_id']) for d in client.list_custom_detectors()])


# parameter -> (what it is, how to list its (name, id) rows)
NAMED_PARAMS = {
    'workspace_id': ('workspace', _workspace_rows),
    'key_id': ('virtual key', _key_rows),
    'policy_ids': ('policy', _policy_rows),
    'guardrail_id': ('guardrail', _guardrail_rows),
    'detector_ids': ('detector', _detector_rows),
}


def _resolve_one(value, kind, rows):
    if not isinstance(value, str) or value.strip() in ('', 'null') or _UUID.match(value.strip()):
        return value
    value = value.strip()
    if any(row[1] == value for row in rows):
        return value
    matches = [row for row in rows if row[0] == value]
    ids = [row[1] for row in matches]
    if len(ids) > 1:
        # a renewed key keeps its name: the one active key is the one meant
        active = [row[1] for row in matches if len(row) < 3 or row[2]]
        if len(active) == 1:
            return active[0]
        raise ConnectorError('More than one {0} is named "{1}"; pass its id instead: {2}'.format(
            kind, value, ', '.join(str(i) for i in ids)))
    # No match: hand it on as given, so the API's own not-found answer reaches the user.
    return ids[0] if ids else value


def resolve_names(client, params) -> dict:
    """Replace each picked dropdown name in `params` with the id the API needs."""
    out = dict(params or {})
    for name, (kind, lister) in NAMED_PARAMS.items():
        value = out.get(name)
        values = value if isinstance(value, (list, tuple)) else [value]
        if not any(isinstance(v, str) and v.strip() not in ('', 'null') and not _UUID.match(v.strip())
                   for v in values):
            continue
        rows = lister(client)
        resolved = [_resolve_one(v, kind, rows) for v in values]
        out[name] = resolved if isinstance(value, (list, tuple)) else resolved[0]
    return out


def _opt(params, name) -> Optional[str]:
    value = params.get(name)
    if value in (None, '', 'null'):
        return None
    return str(value)


def _ids_list(raw) -> list:
    """Accept a multiselect list or a comma-separated string of ids."""
    if raw in (None, '', 'null'):
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw).split(',') if x.strip()]


def list_workspaces(config, params):
    return _client(config).list_workspaces()


operations['list_workspaces'] = list_workspaces


def list_my_workspaces(config, params):
    return _client(config).list_my_workspaces()


operations['list_my_workspaces'] = list_my_workspaces


def list_virtual_keys(config, params):
    return _client(config).list_virtual_keys(
        workspace_id=_opt(params, 'workspace_id'),
        status=_opt(params, 'status'),
    )


operations['list_virtual_keys'] = list_virtual_keys


def get_virtual_key(config, params):
    if not params.get('key_id'):
        raise ValueError('key_id is required')
    return _client(config).get_virtual_key(params['key_id'])


operations['get_virtual_key'] = get_virtual_key


def create_virtual_key(config, params):
    if not params.get('workspace_id') or not params.get('key_name'):
        raise ValueError('workspace_id and key_name are required')
    return _client(config).create_virtual_key(
        workspace_id=params['workspace_id'],
        key_name=params['key_name'],
        expires_at=_opt(params, 'expires_at'),
        tpm=_opt(params, 'tpm'),
        rpm=_opt(params, 'rpm'),
    )


operations['create_virtual_key'] = create_virtual_key


def update_virtual_key(config, params):
    if not params.get('key_id'):
        raise ValueError('key_id is required')
    policy_ids = _ids_list(params.get('policy_ids'))
    return _client(config).update_virtual_key(
        key_id=params['key_id'],
        expires_at=_opt(params, 'expires_at'),
        tpm=_opt(params, 'tpm'),
        rpm=_opt(params, 'rpm'),
        policy_ids=policy_ids or None,
    )


operations['update_virtual_key'] = update_virtual_key


def rotate_virtual_key(config, params):
    key_id = _opt(params, 'key_id')
    api_key = _opt(params, 'api_key')
    if not key_id and api_key:
        key_id = key_id_from_secret(api_key)
    if not key_id:
        raise ValueError('key_id or api_key is required')
    return _client(config).rotate_virtual_key(key_id)


operations['rotate_virtual_key'] = rotate_virtual_key


def _flag(params, name):
    return params.get(name) in (True, 'true', 'True', 1, '1')


def _parse_time(value):
    from datetime import datetime, timezone
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None


def replace_virtual_key(config, params):
    """Issue a working replacement for a virtual key and return its new secret.

    FortiAIGate only rotates a key that is still active; an expired, revoked or
    suspended key "cannot be rotated: mint a new key instead". So an active key is
    rotated in place (same id), and any other key is replaced by a new key in the
    same workspace with the same name, limits and policies. A suspended key is
    revoked once its replacement exists. The new secret is shown once - store it
    straight away (for example in HashiCorp Vault).
    """
    from datetime import datetime, timedelta, timezone
    key_id = _opt(params, 'key_id')
    api_key = _opt(params, 'api_key')
    if not key_id and api_key:
        key_id = key_id_from_secret(api_key)
    if not key_id:
        raise ValueError('key_id or api_key is required')
    client = _client(config)
    old = client.get_virtual_key(key_id)
    now = datetime.now(timezone.utc)
    expires = _parse_time(old.get('expiresAt'))
    if old.get('status') == 'active' and not (expires and expires <= now):
        rotated = client.rotate_virtual_key(key_id)
        return {'method': 'rotated', 'old_key_id': key_id, 'new_key_id': key_id,
                'new_secret': rotated.get('new_secret'), 'key': rotated}

    # A revoked key was shut off on purpose (often a leaked key): never bring it back unasked.
    if old.get('status') == 'revoked' and not _flag(params, 'allow_revoked'):
        raise ConnectorError(
            'Key {0} was revoked, which is deliberate; it is not replaced automatically. '
            'Set Allow Replacing a Revoked Key to replace it anyway.'.format(key_id))
    # Model groups and provider access restrict what a key may use and cannot be copied here:
    # a replacement without them could reach more than the original. Refuse rather than widen.
    uncopied = [name for name in ('modelGroups', 'providerAccess') if old.get(name)]
    if uncopied and not _flag(params, 'allow_uncopied'):
        raise ConnectorError(
            'Key {0} has {1} that a replacement would not inherit, so it could reach more than the '
            'original. Nothing was created. Set Allow Replacement Without Model Access Limits to '
            'create it anyway and apply them yourself.'.format(key_id, ' and '.join(uncopied)))
    workspace = (old.get('workspace') or {}).get('id')
    if not workspace:
        raise ConnectorError('Key {0} has no workspace to create its replacement in'.format(key_id))
    days = _opt(params, 'expires_in_days')
    new_expiry = None
    if days:
        new_expiry = now + timedelta(days=float(days))
    elif expires and _parse_time(old.get('createdAt')):
        new_expiry = now + (expires - _parse_time(old.get('createdAt')))   # the same lifetime again
    created = client.create_virtual_key(
        workspace_id=workspace,
        key_name=_opt(params, 'new_key_name') or old.get('keyName') or 'renewed-key',
        expires_at=new_expiry.strftime('%Y-%m-%dT%H:%M:%S.000Z') if new_expiry else None,
        tpm=None if old.get('tpm') is None else str(old['tpm']),
        rpm=None if old.get('rpm') is None else str(old['rpm']))
    new_id = created.get('id')
    own_policies = [p['id'] for p in (old.get('policyIds') or []) if isinstance(p, dict) and not p.get('assignedByOrg')]
    if own_policies:
        client.update_virtual_key(new_id, policy_ids=own_policies)
    not_copied = uncopied
    revoked = False
    if old.get('status') == 'suspended' and params.get('revoke_old', True) not in (False, 'false', 'False'):
        client.revoke_virtual_key(key_id, 'Replaced by key {0}'.format(new_id))
        revoked = True
    return {'method': 'reissued', 'old_key_id': key_id, 'old_status': old.get('status'), 'old_revoked': revoked,
            'new_key_id': new_id, 'new_secret': created.get('secretKey') or created.get('new_secret'),
            'not_copied': not_copied, 'key': created}


operations['replace_virtual_key'] = replace_virtual_key


def revoke_virtual_key(config, params):
    if not params.get('key_id'):
        raise ValueError('key_id is required')
    return _client(config).revoke_virtual_key(
        params['key_id'], _opt(params, 'reason') or 'Revoked from FortiSOAR')


operations['revoke_virtual_key'] = revoke_virtual_key


def check_key(config, params):
    if not params.get('api_key'):
        raise ValueError('api_key is required')
    return _client(config).check_key(params['api_key'])


operations['check_key'] = check_key


def _parse_messages(raw) -> list:
    import json
    from .connections import ConnectorError
    if isinstance(raw, (list, tuple)):
        return list(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
        except ValueError:
            pass
    raise ConnectorError(
        'messages must be a JSON list, e.g. [{"role": "user", "content": "..."}]')


def chat_completion(config, params):
    if not params.get('api_key') or not params.get('model'):
        raise ValueError('api_key and model are required')
    client = _client(config)
    result = client.chat_completion(
        api_key=params['api_key'],
        model=params['model'],
        messages=_parse_messages(params.get('messages')),
        max_tokens=params.get('max_tokens') or None,
        temperature=params.get('temperature'),
    )
    return result


operations['chat_completion'] = chat_completion


def list_policies(config, params):
    return _client(config).list_policies(workspace_id=_opt(params, 'workspace_id'))


operations['list_policies'] = list_policies


def get_policy(config, params):
    if not params.get('policy_id'):
        raise ValueError('policy_id is required')
    return _client(config).get_policy(params['policy_id'])


operations['get_policy'] = get_policy


def list_guardrails(config, params):
    return _client(config).list_guardrails()


operations['list_guardrails'] = list_guardrails


def get_guardrail(config, params):
    if not params.get('guardrail_id'):
        raise ValueError('guardrail_id is required')
    return _client(config).get_guardrail(params['guardrail_id'])


operations['get_guardrail'] = get_guardrail


def test_guardrail(config, params):
    if not params.get('input_text'):
        raise ValueError('input_text is required')
    detector_ids = _ids_list(params.get('detector_ids'))
    return _client(config).test_guardrail(
        input_text=params['input_text'],
        detector_ids=detector_ids or None,
        guardrail_id=_opt(params, 'guardrail_id'),
        deny_suspicious_characters=bool(params.get('deny_suspicious_characters')),
    )


operations['test_guardrail'] = test_guardrail


def list_ai_providers(config, params):
    return _client(config).list_ai_providers()


operations['list_ai_providers'] = list_ai_providers


def get_workspace_budget(config, params):
    if not params.get('workspace_id'):
        raise ValueError('workspace_id is required')
    return _client(config).get_workspace_budget(params['workspace_id'])


operations['get_workspace_budget'] = get_workspace_budget


def list_audit_logs(config, params):
    return _client(config).list_audit_logs(
        offset=params.get('offset') or 0,
        limit=params.get('limit') or 25,
    )


operations['list_audit_logs'] = list_audit_logs


def get_audit_log_filter_options(config, params):
    return _client(config).get_audit_log_filter_options()


operations['get_audit_log_filter_options'] = get_audit_log_filter_options


# - dropdown populators ("apiOperation" sources, visible: false) -----------
# Update step UIs call these with the connector config only and render the
# result as dropdown options: a plain list of strings (see resolve_names above).


def get_workspace_options(config, params):
    client = _client(config)
    return _names(_workspace_rows(client))


operations['get_workspace_options'] = get_workspace_options


def get_virtual_key_options(config, params):
    return _names(_key_rows(_client(config)))


operations['get_virtual_key_options'] = get_virtual_key_options


def get_policy_options(config, params):
    return _names(_policy_rows(_client(config)))


operations['get_policy_options'] = get_policy_options


def get_guardrail_options(config, params):
    return _names(_guardrail_rows(_client(config)))


operations['get_guardrail_options'] = get_guardrail_options


def get_detector_options(config, params):
    return _names(_detector_rows(_client(config)))


operations['get_detector_options'] = get_detector_options


def get_model_options(config, params):
    """Model names chat completions accept. The org model groups are the
    modeled catalog; without membership to a group there are no options, so
    fall back to empty (the user can still type a free-form model)."""
    groups = _client(config).list_model_groups()
    names = []
    for g in groups:
        names.extend(g.get('_models') or [])
    seen = set()
    ordered = []
    for name in sorted(names):
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


operations['get_model_options'] = get_model_options


def execute_api_request(config, params):
    """Call any FortiAIGate management API endpoint with the configured login.

    `endpoint` is a path on the configured server (for example
    `/api/v1/admin/workspaces`). Methods: GET, POST, PUT, PATCH, DELETE.
    """
    method = (params.get('method') or 'GET').upper()
    if method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
        raise ConnectorError('Method must be GET, POST, PUT, PATCH or DELETE')
    return _client(config).raw(method, params.get('endpoint'),
                               json_object(params.get('query_params'), 'Query Parameters'),
                               json_object(params.get('request_body'), 'Request Body'))


operations['execute_api_request'] = execute_api_request


def _check_health(config):
    return _client(config).health()
