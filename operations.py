"""Operation handlers for the FortiAIGate connector. Each takes
``(config, params)`` and returns a JSON-serializable result."""

from __future__ import annotations

import re
from typing import Optional

from connectors.core.connector import ConnectorError

from .connections import FaigClient, json_object, key_id_from_secret

operations = {}


def _client(config):
    # One execute() shares one client (connector.py), so the login, its role and its
    # workspace are looked up once per action, not once for the names and again for the call.
    if config.get('_faig_client') is not None:
        return config['_faig_client']
    return FaigClient(
        server=config['server'],
        username=config['username'],
        password=config['password'],
        verify_ssl=config.get('verify_ssl', True),
        data_plane_base=config.get('data_plane_base') or None,
        timeout=config.get('timeout') or 30,
        workspace=config.get('workspace') or None,
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


def list_expiring_virtual_keys(config, params):
    """Keys that expire within N days, and (by default) keys that already have.

    A key with no expiry never expires, and a revoked or suspended key was shut
    off on purpose, so neither is listed. Soonest first.
    """
    from datetime import datetime, timedelta, timezone
    within = _days(params, 'within_days', 7, 'Within (Days)', allow_zero=True)
    include_expired = str(_opt(params, 'include_expired') if _opt(params, 'include_expired') is not None
                          else True).lower() not in ('false', '0', 'no')
    now = datetime.now(timezone.utc)
    horizon = now + timedelta(days=within)
    keys = []
    for record in _client(config).list_virtual_keys(workspace_id=_opt(params, 'workspace_id')):
        expires = _parse_time(record.get('expiresAt'))
        status = record.get('status')
        if expires is None or status not in ('active', 'expired') or expires > horizon:
            continue
        expired = status == 'expired' or expires <= now
        if expired and not include_expired:
            continue
        keys.append(dict(record, expired=expired,
                         days_left=round((expires - now).total_seconds() / 86400, 2)))
    keys.sort(key=lambda k: k['days_left'])
    return {'keys': keys, 'key_ids': [k['id'] for k in keys], 'count': len(keys),
            'within_days': within, 'checked_at': _iso(now)}


operations['list_expiring_virtual_keys'] = list_expiring_virtual_keys


def get_virtual_key(config, params):
    if not params.get('key_id'):
        raise ValueError('key_id is required')
    return _client(config).get_virtual_key(params['key_id'])


operations['get_virtual_key'] = get_virtual_key


def create_virtual_key(config, params):
    client = _client(config)
    if not params.get('key_name') or (client.org_scope and not params.get('workspace_id')):
        raise ValueError('workspace_id and key_name are required')
    expires_at = _opt(params, 'expires_at')
    if not expires_at and _opt(params, 'expires_in_days') not in (None, ''):
        from datetime import datetime, timedelta, timezone
        days = _days(params, 'expires_in_days', 30, 'Expires In (Days)')
        expires_at = _iso(datetime.now(timezone.utc) + timedelta(days=days))
    return client.create_virtual_key(
        workspace_id=_opt(params, 'workspace_id'),
        key_name=params['key_name'],
        expires_at=expires_at,
        tpm=_opt(params, 'tpm'),
        rpm=_opt(params, 'rpm'),
        provider_ids=_ids_list(params.get('provider_ids')),
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


def _parse_time(value):
    from datetime import datetime, timezone
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None


def _days(params, name, default, title, allow_zero=False):
    value = _opt(params, name)
    try:
        days = float(value) if value not in (None, '') else float(default)
    except (TypeError, ValueError):
        raise ConnectorError('{0} must be a number of days'.format(title))
    if not 0 <= days <= 3650 or (days == 0 and not allow_zero):
        raise ConnectorError('{0} must be between 0 and 3650, not {1:g}'.format(title, days))
    return days


def _iso(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def renew_virtual_key(config, params):
    """Give a virtual key a new secret, keeping its id, name, limits and policies.

    The key's expiry is moved to Extend By (Days) from now when it would come
    sooner - so a key renewed before it expires does not expire anyway a few
    days later - and is never shortened. An expired key needs this too:
    FortiAIGate only rotates an active key ("cannot be rotated: mint a new key
    instead"), and an expired key becomes active again when its expiry moves
    into the future. Then the key is rotated. A key with no expiry is only
    rotated. A revoked or suspended key is refused and left untouched. The new
    secret is shown once - store it straight away (for example in HashiCorp Vault).
    """
    from datetime import datetime, timedelta, timezone
    key_id = _opt(params, 'key_id')
    api_key = _opt(params, 'api_key')
    if not key_id and api_key:
        key_id = key_id_from_secret(api_key)
    if not key_id:
        raise ValueError('key_id or api_key is required')
    days = _days(params, 'expires_in_days', 30, 'Extend By (Days)')
    client = _client(config)
    old = client.get_virtual_key(key_id)
    status = old.get('status')
    now = datetime.now(timezone.utc)
    expires = _parse_time(old.get('expiresAt'))
    expired = status == 'expired' or (status == 'active' and expires is not None and expires <= now)
    if not expired and status != 'active':
        raise ConnectorError(
            'Key {0} is {1}; only an active or expired key can be renewed.{2}'.format(
                key_id, status, ' A revoked key was shut off on purpose.' if status == 'revoked' else ''))
    target = now + timedelta(days=days)
    extend = expired or (expires is not None and expires < target)
    new_expiry = _iso(target) if extend else None
    if extend:
        client.update_virtual_key(key_id, expires_at=new_expiry)
    try:
        rotated = client.rotate_virtual_key(key_id)
    except Exception:
        # Undo the extend. For an expired key it made the OLD secret work again, so
        # never leave it that way: put the original expiry back (a past date expires
        # the key again) or, failing that, revoke.
        if extend:
            try:
                if not old.get('expiresAt'):
                    raise ConnectorError('no original expiry to restore')
                client.update_virtual_key(key_id, expires_at=old['expiresAt'])
            except Exception:
                if expired:
                    client.revoke_virtual_key(key_id, 'Renewal failed after the expiry was extended')
        raise
    return {'method': 'extended_and_rotated' if extend else 'rotated', 'key_id': key_id,
            'old_status': status, 'old_expires_at': old.get('expiresAt'),
            'expires_at': new_expiry or old.get('expiresAt'),
            'new_secret': rotated.get('new_secret'), 'key': rotated}


operations['renew_virtual_key'] = renew_virtual_key


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
    client = _client(config)
    workspace_id = _opt(params, 'workspace_id')
    if not workspace_id:
        if client.org_scope:
            raise ValueError('workspace_id is required')
        workspace_id = client.default_workspace()
    return client.get_workspace_budget(workspace_id)


operations['get_workspace_budget'] = get_workspace_budget


def list_audit_logs(config, params):
    return _client(config).list_audit_logs(
        offset=params.get('offset') or 0,
        limit=params.get('limit') or 25,
    )


operations['list_audit_logs'] = list_audit_logs


def get_traffic_log(config, params):
    """One traffic-log record by its FortiAIGate request id (``uuid``).

    Used by the revocation playbook to verify a guardrail-block event. The
    traffic log names the virtual key only by ``keyAlias`` (name) and
    ``keyPrefix`` (secret preview, not the key id), so this op looks up the
    key in the matching workspace and returns its id. The playbook can then
    confirm the key_id the caller named is the one that was blocked.

    ``verdict`` is normalised to lowercase (``block``/``allow``) regardless
    of whether the gateway returned a boolean or an ``action`` string
    (``DENY``/``ALLOW``), so a decision step can match on either.
    """
    if not params.get('request_id'):
        raise ValueError('request_id is required')
    client = _client(config)
    log = client.traffic_log(params['request_id'])
    verdict_raw = log.get('verdict')
    action = str(log.get('action') or '').upper()
    if isinstance(verdict_raw, bool):
        verdict = 'block' if verdict_raw else 'allow'
    else:
        verdict = str(verdict_raw or '').lower()
    if not verdict:
        verdict = 'block' if action == 'DENY' else ('allow' if action == 'ALLOW' else '')
    # Resolve the key the log names. Prefix (last chars of the secret) is in the
    # key record's keyPreview; same-named keys are disambiguated by it.
    alias = str(log.get('keyAlias') or '')
    prefix = str(log.get('keyPrefix') or '')
    ws = log.get('workspace') or ''
    key_id, key_name = '', alias
    if alias:
        # list ALL keys the login can see, then filter by alias. Narrow by workspace only
        # when the key record carries one that matches; records without a workspace field are
        # kept (older FAIG shapes). ws from the log is a name, which connections.list_virtual_keys
        # does not resolve.
        # Fail CLOSED: require that the log's keyPrefix matches the key record's keyPreview
        # whenever the log carries a prefix (same-named keys share the alias; prefix uniquely
        # identifies the secret). Workspace is only used to narrow when both sides carry it.
        def _ws_matches(k):
            wk = k.get('workspace')
            if not wk or not ws:
                return True
            if isinstance(wk, dict):
                return wk.get('name') == ws or wk.get('id') == ws
            return wk == ws
        candidates = [k for k in client.list_virtual_keys()
                      if str(k.get('keyName') or '') == alias and _ws_matches(k)]
        if prefix:
            candidates = [k for k in candidates if str(k.get('keyPreview') or '') == prefix]
        if len(candidates) == 1:
            key_id = str(candidates[0].get('id') or '')
            key_name = str(candidates[0].get('keyName') or alias)
    return {
        'uuid': log.get('uuid') or log.get('requestId'),
        'keyId': key_id,
        'keyName': key_name,
        'keyPrefix': prefix,
        'verdict': verdict,
        'action': action,
        'timeStamp': log.get('timeStamp'),
        'workspace': ws,
        'user': log.get('user') or '',
        'model': log.get('model') or '',
        'requestPath': log.get('requestPath') or '',
        'detector': _detector_names(log.get('violation') or log.get('detector')),
    }


def _detector_names(violation):
    """Strip prompt/response and violation details; keep only detector names and type.
    A traffic log carries the user's prompt and the model's response in cleartext;
    returning them from this op would persist them in debug-mode run history."""
    names = []
    if isinstance(violation, dict):
        for side, hits in violation.items():
            if not hits:
                continue
            for h in (hits if isinstance(hits, list) else [hits]):
                if isinstance(h, dict):
                    names.append({'name': str(h.get('detectorName') or h.get('name') or ''),
                                  'type': str(h.get('type') or ''),
                                  'side': str(side)})
    return names


operations['get_traffic_log'] = get_traffic_log


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
