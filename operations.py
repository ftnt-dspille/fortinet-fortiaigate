"""Operation handlers for the FortiAIGate connector. Each takes
``(config, params)`` and returns a JSON-serializable result."""

from __future__ import annotations

from typing import Optional

from .connections import FaigClient, key_id_from_secret

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


def revoke_virtual_key(config, params):
    if not params.get('key_id'):
        raise ValueError('key_id is required')
    return _client(config).revoke_virtual_key(params['key_id'])


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
# result as [{title, value}] dropdown options. Plain string lists are also
# accepted by the UI; we always return title/value so users see names while
# playbooks receive stable ids.


def get_workspace_options(config, params):
    client = _client(config)
    workspaces = client.list_my_workspaces() or client.list_workspaces()
    return [{'title': w.get('_workspaceName') or w.get('workspaceName'),
             'value': w.get('_id') or w.get('id')} for w in workspaces]


operations['get_workspace_options'] = get_workspace_options


def get_virtual_key_options(config, params):
    keys = _client(config).list_virtual_keys()
    return [{'title': '{0} ({1})'.format(k.get('keyName'), k.get('status')),
             'value': k.get('id')} for k in keys]


operations['get_virtual_key_options'] = get_virtual_key_options


def get_policy_options(config, params):
    policies = _client(config).list_policies()
    return [{'title': '{0} ({1})'.format(p.get('name'), p.get('status')),
             'value': p.get('id')} for p in policies]


operations['get_policy_options'] = get_policy_options


def get_guardrail_options(config, params):
    guardrails = _client(config).list_guardrails()
    return [{'title': '{0} ({1})'.format(g.get('name'), g.get('status')),
             'value': g.get('id')} for g in guardrails]


operations['get_guardrail_options'] = get_guardrail_options


def get_detector_options(config, params):
    client = _client(config)
    options = []
    for d in client.list_builtin_detectors():
        options.append({'title': '{0} [built-in]'.format(d['_name']),
                        'value': d['_id']})
    for d in client.list_custom_detectors():
        options.append({'title': '{0} [workspace]'.format(d['_name']),
                        'value': d['_id']})
    return options


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


def _check_health(config):
    return _client(config).health()
