"""Operation handlers for the FortiAIGate connector. Each takes ``(config, params)``
and returns a JSON-serializable result.

The HTTP client is pyfortiaigate's ``FortiAIGate``. It logs in, routes every call
to the right scope (an organization administrator's ``/api/v1/admin`` paths, or a
workspace login's own workspace), and resolves names to ids for workspaces, keys,
policies, guardrails and detectors. This module maps the connector's parameters
onto those methods, and keeps the SOAR-specific parts: the dropdown lists, the
endpoint guard of Execute API Request, and the blocked-traffic ingestion read.
"""

from __future__ import annotations

import http.client
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import unquote, urlparse

from connectors.core.connector import ConnectorError
from pyfortiaigate import FaigError, FortiAIGate, key_id_from_secret

operations = {}

# What the library raises for an API answer (FaigError), a name it cannot find
# (LookupError), or a connection that failed (OSError, HTTPException). The connector
# turns these into a ConnectorError, which FortiSOAR shows as the message.
API_ERRORS = (FaigError, LookupError, OSError, http.client.HTTPException)

# /api/v1/me/workspaces names a membership "admin" or "member" on 8.0.2 (user records
# say "workspace_admin"/"workspace_member"); accept both spellings.
MEMBER_ROLES = ('member', 'workspace_member')
NEEDS_WS_ADMIN = 'Workspace administrator access required'
NEEDS_ORG_ADMIN = 'Organization-level access required'


def member_message(username) -> str:
    return ('{0} is only a member of its FortiAIGate workspace. FortiAIGate lets only a '
            'workspace admin read keys, guardrails, policies and logs or revoke keys: make this '
            'user a workspace admin, or use an organization administrator.'.format(username))


def friendly_error(err, username) -> str:
    """The message a SOAR user sees: a role refusal says what to change, then the
    gateway's own answer."""
    text = str(err)
    if isinstance(err, ValueError) and text.endswith('pass workspace= or ws_id'):
        return text.replace('pass workspace= or ws_id',
                            'set Workspace in the configuration, or choose one in this action')
    if getattr(err, 'status', None) == 403 and NEEDS_WS_ADMIN in text:
        return '{0} ({1})'.format(member_message(username), text)
    if getattr(err, 'status', None) == 403 and NEEDS_ORG_ADMIN in text:
        return ('This action needs a FortiAIGate organization administrator; {0} is a workspace '
                'login. ({1})'.format(username, text))
    return text


def _int_opt(params, name):
    """An optional whole number (FortiAIGate 422s a numeric string)."""
    value = _opt(params, name)
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        raise ValueError('{0} must be a whole number, not {1!r}'.format(name, value)) from None


def _client(config):
    # One execute() shares one client (connector.py), so the login and the role are
    # looked up once per action.
    if config.get('_faig_client') is not None:
        return config['_faig_client']
    return FortiAIGate(
        config['server'],
        config['username'],
        config['password'],
        verify=config.get('verify_ssl', True),
        timeout=float(config.get('timeout') or 30),
        gateway_url=config.get('data_plane_base') or None,
        workspace=config.get('workspace') or None,
    )


def _opt(params, name) -> Optional[str]:
    value = params.get(name)
    if value in (None, '', 'null'):
        return None
    return str(value)


def _required(params, name) -> str:
    value = _opt(params, name)
    if value is None:
        raise ValueError('{0} is required'.format(name))
    return value


def _key_ref(params) -> str:
    """The virtual key to act on: its id or name, else the secret it was issued as."""
    ref = _opt(params, 'key_id')
    if ref:
        return ref
    secret = _opt(params, 'api_key')
    if not secret:
        raise ValueError('key_id or api_key is required')
    # The secret embeds the key id: derive it here so the secret itself never
    # reaches a name lookup, whose "no key named ..." error would echo it.
    return key_id_from_secret(secret)


def _ids_list(raw) -> list:
    """Accept a multiselect list or a comma-separated string of ids or names."""
    if raw in (None, '', 'null'):
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return [x.strip() for x in str(raw).split(',') if x.strip()]


def _json_object(value, name) -> Optional[dict]:
    """A JSON object from a dict or a JSON string; blank means none."""
    if value in (None, '', {}):
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            raise ConnectorError('{0} must be valid JSON'.format(name))
    if not isinstance(value, dict):
        raise ConnectorError('{0} must be a JSON object'.format(name))
    return value


def _endpoint(endpoint) -> str:
    """A path on the configured server. A full URL, a //host start or a `..` segment
    (also percent-encoded) is refused, so the session cookie and CSRF token never go
    to another host."""
    endpoint = str(endpoint or '').strip()
    if not endpoint:
        raise ConnectorError('Endpoint is required')
    path = endpoint.split('?')[0]
    for _ in range(3):
        path = unquote(path)
    parsed = urlparse(endpoint)
    if (parsed.scheme or parsed.netloc or endpoint.startswith('//')
            or '..' in path.split('/') or '\\' in path):
        raise ConnectorError('Endpoint must be a path on the configured server, '
                             'for example /api/v1/admin/workspaces - not a full URL')
    return endpoint if endpoint.startswith('/') else '/' + endpoint


def _workspaces(client):
    """Every workspace for an organization administrator, the login's own otherwise."""
    return client.workspaces() if client.org_scope else client.my_workspaces()


def _names(names) -> list:
    """The distinct non-empty names, in order: a plain list for a dropdown."""
    return list(dict.fromkeys(str(n) for n in names if n))


# - workspaces, keys, policies, guardrails, detectors ------------------------------


def list_workspaces(config, params):
    return _workspaces(_client(config))


operations['list_workspaces'] = list_workspaces


def list_my_workspaces(config, params):
    return _client(config).my_workspaces()


operations['list_my_workspaces'] = list_my_workspaces


def list_virtual_keys(config, params):
    return _client(config).virtual_keys(_opt(params, 'workspace_id'), status=_opt(params, 'status'))


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
    for record in _client(config).virtual_keys(_opt(params, 'workspace_id')):
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
    return _client(config).virtual_key(_required(params, 'key_id'))


operations['get_virtual_key'] = get_virtual_key


def create_virtual_key(config, params):
    client = _client(config)
    workspace = _opt(params, 'workspace_id') or client.default_workspace()
    if not workspace:
        raise ValueError('workspace_id is required')
    # Caller may pass explicit provider_ids; otherwise auto-grant every provider the
    # workspace has an enabled model from, because 8.0.2 refuses a key with no model
    # access (422 "At least one model or model group is required").
    explicit = _ids_list(params.get('provider_ids'))
    if explicit:
        providers = explicit
    else:
        providers = [p['providerId'] for p in client.grantable_providers(workspace)
                     if any(m.get('effectiveEnabled', m.get('enabled')) for m in p.get('models') or [])]
    expires_at = _opt(params, 'expires_at')
    if not expires_at and _opt(params, 'expires_in_days') not in (None, ''):
        days = _days(params, 'expires_in_days', 30, 'Expires In (Days)')
        expires_at = _iso(datetime.now(timezone.utc) + timedelta(days=days))
    return client.create_virtual_key(
        workspace,
        _required(params, 'key_name'),
        provider_ids=providers or None,
        expires_at=expires_at,
        tpm=_int_opt(params, 'tpm'),
        rpm=_int_opt(params, 'rpm'),
    )


operations['create_virtual_key'] = create_virtual_key


def update_virtual_key(config, params):
    return _client(config).update_virtual_key(
        _required(params, 'key_id'),
        expires_at=_opt(params, 'expires_at'),
        tpm=_int_opt(params, 'tpm'),
        rpm=_int_opt(params, 'rpm'),
        policy_ids=_ids_list(params.get('policy_ids')) or None,
    )


operations['update_virtual_key'] = update_virtual_key


def rotate_virtual_key(config, params):
    return _client(config).rotate_virtual_key(_key_ref(params))


operations['rotate_virtual_key'] = rotate_virtual_key


def _parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None


def _days(params, name, default, title, allow_zero=False):
    """Clamp a caller-supplied number-of-days to the 0 - 3650 range (master 1.6.6)."""
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
    instead"), but an expired key becomes active again when its expiry moves into
    the future. So pyfortiaigate extends an expired key (and any key whose expiry
    would come sooner than Extend By) and then rotates it; an active key with a
    far-off expiry is rotated straight away; a key with no expiry is only rotated.
    A revoked or suspended key is refused and left untouched. If the rotate fails
    after an extend, the original expiry is put back (an expired key is revoked
    if that also fails), so the old secret never stays working. The new secret
    is shown once - store it straight away (for example in HashiCorp Vault).
    """
    ref = _key_ref(params)
    days = _days(params, 'expires_in_days', 30, 'Extend By (Days)')
    try:
        renewed = _client(config).renew_virtual_key(ref, expires_in_days=days)
    except ValueError as err:  # a revoked or suspended key, or days out of range
        raise ConnectorError(str(err))
    return {
        'method': renewed.method,
        'key_id': renewed.key_id,
        'old_status': renewed.old_status,
        'old_expires_at': getattr(renewed, 'old_expires_at', None),
        'expires_at': renewed.expires_at,
        'secretKey': renewed.secret,
        'new_secret': renewed.secret,
        'key': {k: v for k, v in renewed.record.items() if k != 'secretKey'},
    }


operations['renew_virtual_key'] = renew_virtual_key


def revoke_virtual_key(config, params):
    return _client(config).revoke_virtual_key(
        _required(params, 'key_id'), _opt(params, 'reason') or 'Revoked from FortiSOAR')


operations['revoke_virtual_key'] = revoke_virtual_key


def check_key(config, params):
    return _client(config).check_key(_required(params, 'api_key'))


operations['check_key'] = check_key


def list_policies(config, params):
    return _client(config).policies(_opt(params, 'workspace_id'))


operations['list_policies'] = list_policies


def get_policy(config, params):
    return _client(config).policy(_required(params, 'policy_id'))


operations['get_policy'] = get_policy


def list_guardrails(config, params):
    return _client(config).guardrails()


operations['list_guardrails'] = list_guardrails


def get_guardrail(config, params):
    return _client(config).guardrail(_required(params, 'guardrail_id'))


operations['get_guardrail'] = get_guardrail


def test_guardrail(config, params):
    detector_ids = _ids_list(params.get('detector_ids'))
    guardrail_id = _opt(params, 'guardrail_id')
    if not detector_ids and not guardrail_id:
        raise ValueError('detector_ids or guardrail_id is required')
    return _client(config).test_guardrail(
        _required(params, 'input_text'),
        detector_ids or None,
        guardrail_id=guardrail_id,
        deny_suspicious_characters=bool(params.get('deny_suspicious_characters')),
    )


operations['test_guardrail'] = test_guardrail


def list_ai_providers(config, params):
    client = _client(config)
    if not client.org_scope:
        raise ConnectorError(
            'Listing AI providers needs an organization administrator; {0} is a {1} login. '
            'List Policies shows the providers your workspace may use.'.format(
                config.get('username'), client.role))
    return client.ai_providers()


operations['list_ai_providers'] = list_ai_providers


def get_workspace_budget(config, params):
    client = _client(config)
    workspace = _opt(params, 'workspace_id') or client.default_workspace()
    if not workspace:
        raise ValueError('workspace_id is required')
    return client.workspace_budget(workspace)


operations['get_workspace_budget'] = get_workspace_budget


# - chat, models, audit -------------------------------------------------------------


def _parse_messages(raw) -> list:
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
    """One OpenAI-compatible chat completion through the gateway. The key's policies
    and guardrails apply; a block comes back as a completion with finish_reason
    content_filter, not as an error."""
    api_key = _required(params, 'api_key')
    model = _required(params, 'model')
    return _client(config).chat_completion(
        api_key,
        model,
        _parse_messages(params.get('messages')),
        max_tokens=_opt(params, 'max_tokens'),
        temperature=_opt(params, 'temperature'),
    )


operations['chat_completion'] = chat_completion


def list_audit_logs(config, params):
    return _client(config).audit_logs_page(
        _opt(params, 'cursor'),
        range=_opt(params, 'range') or 'all',
        limit=int(params.get('limit') or 25),
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
        # kept (older FAIG shapes). ws from the log is a name, which virtual_keys
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
        candidates = [k for k in client.virtual_keys()
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
    return _client(config).audit_log_filter_options()


operations['get_audit_log_filter_options'] = get_audit_log_filter_options


def execute_api_request(config, params):
    """Call any FortiAIGate management API endpoint with the configured login.

    `endpoint` is a path on the configured server (for example
    `/api/v1/admin/workspaces`). Methods: GET, POST, PUT, PATCH, DELETE.
    """
    method = (params.get('method') or 'GET').upper()
    if method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
        raise ConnectorError('Method must be GET, POST, PUT, PATCH or DELETE')
    return _client(config).request(
        method,
        _endpoint(params.get('endpoint')),
        body=_json_object(params.get('request_body'), 'Request Body'),
        params=_json_object(params.get('query_params'), 'Query Parameters'),
    )


operations['execute_api_request'] = execute_api_request


# - blocked traffic (scheduled ingestion) ----------------------------------------------


def _when(value, name) -> Optional[datetime]:
    """A time as an aware UTC datetime: epoch milliseconds (an int or digits) or an
    ISO-8601 datetime such as 2026-10-15T10:00:00Z (a naive one is taken as UTC)."""
    if value in (None, '', 'null'):
        return None
    if isinstance(value, bool):
        raise ValueError('{0} must be epoch milliseconds or an ISO datetime'.format(name))
    if isinstance(value, (int, float)) or re.fullmatch(r'-?\d+', str(value).strip()):
        return datetime.fromtimestamp(int(float(value)) / 1000, timezone.utc)
    text = str(value).strip()
    iso = text[:-1] + '+00:00' if text[-1:] in ('Z', 'z') else text
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        raise ValueError('{0} must be epoch milliseconds or an ISO datetime such as '
                         '2026-10-15T10:00:00Z, not {1!r}'.format(name, text))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def get_blocked_traffic(config, params):
    """Requests FortiAIGate blocked, newest first: what was sent, the detectors that
    fired and why, and the virtual key that sent it.

    `since` (the last pull time) with an optional `until` (default now) is a custom
    window. Without `since`, `range` (24h, 7d, month or all) counts back from now.
    `max_items` caps the rows read; the cap keeps the newest, so a poller that
    needs every row should run often enough that one window stays under it.
    """
    since = _when(params.get('since'), 'since')
    until = _when(params.get('until'), 'until')
    if until is not None and since is None:
        raise ValueError('until needs since: a custom window runs from since to until; '
                         'leave both blank to read the range instead')
    if since is not None and until is not None and until <= since:
        raise ValueError('until must be later than since')
    max_items = int(params.get('max_items') or 100)
    if max_items < 1:
        raise ValueError('max_items must be at least 1')
    records = _client(config).blocked_requests(
        since=since,
        until=until,
        range=_opt(params, 'range') or '24h',
        max_items=max_items,
        ws_id=_opt(params, 'workspace_id'),
    )
    teams = _owner_teams(config)
    for record in records:
        record['ownerTeams'] = teams
    return records


def _owner_teams(config) -> list:
    """The team IRIs that own this connector configuration, so the ingestion can make
    the alerts theirs. Without owners an alert goes to the playbook's default team, which
    a student on a Private configuration cannot read. Read in the connector, not the
    playbook: the configuration API also returns the encrypted password, which would
    land in the run log. Empty when the configuration is shared or the lookup fails."""
    config_id = config.get('config_id')
    if not config_id:
        return []
    try:
        from integrations.crudhub import make_request
        found = make_request('/api/integration/configuration/{0}/'.format(config_id), 'GET')
    except Exception:  # noqa: BLE001 - ownership is a nicety; never fail the read on it
        return []
    teams = found.get('teams') if isinstance(found, dict) else None
    return ['/api/3/teams/{0}'.format(str(t).rsplit('/', 1)[-1]) for t in teams or [] if t]


operations['get_blocked_traffic'] = get_blocked_traffic


# - dropdown populators ("apiOperation" sources, visible: false) -----------
# Update step UIs call these with the connector config only and render the
# result as dropdown options: a plain list of strings. The action then receives
# the picked name, which the library resolves to the id.


def get_workspace_options(config, params):
    return _names(w.get('workspaceName') for w in _workspaces(_client(config)))


operations['get_workspace_options'] = get_workspace_options


def get_virtual_key_options(config, params):
    return _names(k.get('keyName') for k in _client(config).virtual_keys())


operations['get_virtual_key_options'] = get_virtual_key_options


def get_policy_options(config, params):
    return _names(p.get('name') for p in _client(config).policies())


operations['get_policy_options'] = get_policy_options


def get_guardrail_options(config, params):
    return _names(g.get('name') for g in _client(config).guardrails())


operations['get_guardrail_options'] = get_guardrail_options


def get_detector_options(config, params):
    client = _client(config)
    return _names([d.get('name') for d in client.detectors()]
                  + [d.get('name') for d in client.builtin_detectors()])


operations['get_detector_options'] = get_detector_options


def get_model_options(config, params):
    """Model names chat completions accept: the members of the model groups the login
    can use. Without membership to a group there are no options, so the list is
    empty and the user can still type a model name."""
    names = []
    for group in _client(config).model_groups():
        for member in group.get('members') or []:
            model = (member or {}).get('model') or {}
            name = model.get('publicName') or model.get('modelId')
            if name:
                names.append(str(name))
    return sorted(set(names))


operations['get_model_options'] = get_model_options


def _check_health(config):
    """Log in and settle the scope. A workspace login must resolve its workspace now,
    so a wrong Workspace name fails here rather than mid-playbook. A login in several
    workspaces with none configured still passes, since each action can name one."""
    client = _client(config)
    try:
        client.me()
        if not client.org_scope:
            mine = client.my_workspaces()
            if not config.get('workspace') and len(mine) > 1:
                # Nearly every action works in one workspace; without Workspace each would fail.
                raise ConnectorError(
                    '{0} is a member of {1} workspaces ({2}): set Workspace in the configuration.'.format(
                        config.get('username'), len(mine),
                        ', '.join(str(w.get('workspaceName')) for w in mine)))
            ws = client.default_workspace()
            role = next((w.get('membershipRole') for w in mine if str(w.get('id')) == ws), None)
            if role in MEMBER_ROLES:
                # Live-verified on 8.0.2: a workspace member gets 403 "Workspace administrator
                # access required" on keys, guardrails, policies, detectors and traffic logs.
                raise ConnectorError(member_message(config.get('username')))
    except (ValueError, *API_ERRORS) as err:
        raise ConnectorError(str(err))
    return 'ok'
