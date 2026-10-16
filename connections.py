"""Typed FortiAIGate management client used by the connector operations.

Talks to the FortiAIGate 8.x admin console JSON API:

- ``POST /api/v1/login`` with username/password returns a session cookie
  plus a first CSRF token.
- Every mutating method (POST/PUT/PATCH/DELETE) must send a fresh
  ``X-CSRF-Token`` header, obtained per mutation from ``GET /api/csrf-token``.
- Virtual keys live under ``/api/v1/admin/virtual-keys``; their *secret* is
  returned exactly once, at create/rotate time, and never readable again.
- The ``/api/v1/admin/*`` paths need an organization administrator. Any other
  login (a workspace admin or member) gets 403 "Organization-level access
  required" there, so the client reads the login's role from ``GET
  /api/v1/user`` and, for a workspace login, calls the same resources under
  ``/api/v1/workspaces/{id}/*`` instead (workspace scope).
- The data plane is the OpenAI-compatible gateway under
  ``{data_plane_base}/ai/openai/v1``; a virtual key is valid there while its
  record is active and unexpired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Optional
from urllib.parse import unquote, urlparse

import requests

from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('fortinet-fortiaigate')

# Roles that may call /api/v1/admin/*; every other role is scoped to its workspaces.
ORG_ROLES = ('super_admin', 'org_admin')
ORG_ONLY = 'Organization-level access required'
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
# Which disposition wins when several detectors match.
DISPOSITION_RANK = {'log': 1, 'alert': 2, 'redact': 3, 'block': 4}

SECRET_RESPONSE_FIELDS = (
    'secretKey', 'secret_key', 'apiKey', 'api_key', 'newKey', 'new_key', 'key',
)

# Fields a virtual-key PUT accepts; every other field of the GET is read-only.
KEY_WRITABLE = (
    'keyName', 'expiresAt', 'tpm', 'rpm', 'policyIds', 'providerAccess',
    'modelGroups', 'budgetWindows',
)


def key_id_from_secret(api_key: str) -> str:
    """A virtual key secret embeds its record id: faig_<uuid-no-dashes>_...

    The id is recovered from the secret by re-inserting the UUID dashes,
    so callers that hold the secret do not need to look the record up.
    """
    parts = str(api_key).split('_')
    bare = parts[1] if len(parts) > 1 and parts[0] == 'faig' else ''
    if not re.fullmatch(r'[0-9a-fA-F]{32}', bare):
        raise ConnectorError('That is not a FortiAIGate virtual key secret (expected faig_<32 hex>_...); '
                             'pass the key id instead')
    return '-'.join((bare[:8], bare[8:12], bare[12:16], bare[16:20], bare[20:]))


def _seg(value) -> str:
    """One URL path segment. Ids reach paths from playbook input (an API body, a
    Vault metadata tag), so '/' and '..' must not be able to steer the admin
    session to another route."""
    from urllib.parse import quote
    text = str(value if value is not None else '').strip()
    if text in ('', '.', '..'):
        # quote() leaves dots alone, so '..' would still climb a level.
        raise ConnectorError('Invalid id {0!r}: an id cannot be empty, "." or ".."'.format(text))
    return quote(text, safe='')


def normalize_server(server: str) -> str:
    server = (server or '').strip().rstrip('/')
    if not server:
        raise ConnectorError('Server URL is required')
    if not (server.startswith('http://') or server.startswith('https://')):
        server = 'https://' + server
    return server


def safe_endpoint(endpoint: Any) -> str:
    """A path on the configured server, or an error.

    A full URL, a `//host` start, a `..` segment (also percent-encoded, up to
    three layers) or a backslash is refused, so the session and CSRF token can
    never be sent to another host.
    """
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


def json_object(value: Any, name: str) -> Optional[dict]:
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


@dataclass
class VirtualKey:
    id: str
    key_name: str
    status: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    preview: Optional[str] = None
    workspace: Optional[Any] = None
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'VirtualKey':
        return cls(
            id=record.get('id', ''),
            key_name=record.get('keyName', ''),
            status=record.get('status', ''),
            expires_at=record.get('expiresAt'),
            last_used_at=record.get('lastUsedAt'),
            preview=record.get('keyPreview'),
            workspace=record.get('workspace'),
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _id=self.id, _keyName=self.key_name,
                    _status=self.status)


@dataclass
class Workspace:
    id: str
    name: str
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'Workspace':
        return cls(id=record.get('id', ''),
                   name=record.get('workspaceName', ''),
                   raw=record)

    def to_dict(self) -> dict:
        return dict(self.raw, _id=self.id, _workspaceName=self.name)


@dataclass
class Policy:
    id: str
    name: str
    status: str
    input_guardrail_ids: list = field(default_factory=list)
    output_guardrail_ids: list = field(default_factory=list)
    provider_access: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'Policy':
        return cls(
            id=record.get('id', ''),
            name=record.get('name', ''),
            status=record.get('status', ''),
            input_guardrail_ids=record.get('inputGuardrailIds') or [],
            output_guardrail_ids=record.get('outputGuardrailIds') or [],
            provider_access=record.get('providerAccess') or [],
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _id=self.id, _name=self.name, _status=self.status)


@dataclass
class Guardrail:
    id: str
    name: str
    detector_ids: list = field(default_factory=list)
    deny_suspicious_characters: bool = False
    status: str = ''
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'Guardrail':
        return cls(
            id=record.get('id', ''),
            name=record.get('name', ''),
            detector_ids=record.get('detectorIds') or [],
            deny_suspicious_characters=bool(record.get('denySuspiciousCharacters', False)),
            status=record.get('status', ''),
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _id=self.id, _name=self.name,
                    _detectorIds=self.detector_ids)


@dataclass
class DetectorVerdict:
    detector_id: str
    matched: bool
    disposition: str
    score: float
    details: str
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'DetectorVerdict':
        return cls(
            detector_id=record.get('detectorId', ''),
            matched=bool(record.get('matched')),
            disposition=record.get('finalDisposition', ''),
            score=float(record.get('score') or 0.0),
            details=record.get('details', ''),
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _detectorId=self.detector_id, _matched=self.matched,
                    _finalDisposition=self.disposition)


@dataclass
class GuardrailTestResult:
    disposition: str
    matched: bool
    verdicts: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, body: dict) -> 'GuardrailTestResult':
        verdicts = [DetectorVerdict.from_api(r) for r in body.get('results', [])]
        return cls(
            disposition=body.get('finalDisposition', ''),
            matched=any(v.matched for v in verdicts),
            verdicts=verdicts,
            raw=body,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, matched=self.matched,
                    verdicts=[v.to_dict() for v in self.verdicts])


@dataclass
class AiProvider:
    provider_id: str
    label: str
    model_count: int
    key_count: int
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'AiProvider':
        return cls(
            provider_id=record.get('providerId', ''),
            label=record.get('label', record.get('providerId', '')),
            model_count=int(record.get('modelCount') or 0),
            key_count=int(record.get('keyCount') or 0),
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _providerId=self.provider_id, _label=self.label)


@dataclass
class ChatResult:
    content: str
    model: str
    finish_reason: str
    usage: dict
    raw: dict

    @classmethod
    def from_response(cls, body: dict) -> 'ChatResult':
        choice = (body.get('choices') or [{}])[0]
        message = choice.get('message') or {}
        return cls(
            content=message.get('content', ''),
            model=body.get('model', ''),
            finish_reason=choice.get('finish_reason', ''),
            usage=body.get('usage') or {},
            raw=body,
        )

    def to_dict(self) -> dict:
        return {'content': self.content, 'model': self.model,
                'finish_reason': self.finish_reason, 'usage': self.usage,
                'raw': self.raw}


@dataclass
class Detector:
    """A guardrail detector. Custom detectors are identified by uuid and
    created in a workspace; built-in detectors are identified by a slug id
    and belong to a category. Guardrail detectorIds may be either."""
    id: str
    name: str
    builtin: bool
    category: str = ''
    scope: str = ''
    engine: str = ''
    action: str = ''
    status: str = ''
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_custom(cls, record: dict) -> 'Detector':
        return cls(
            id=record.get('uuid', ''),
            name=record.get('name', ''),
            builtin=False,
            category=record.get('category', ''),
            scope=record.get('scope', ''),
            engine=record.get('engine', ''),
            action=record.get('action', ''),
            status=record.get('approvalStatus', ''),
            raw=record,
        )

    @classmethod
    def from_builtin(cls, record: dict) -> 'Detector':
        return cls(
            id=record.get('id', ''),
            name=record.get('name', ''),
            builtin=True,
            category=record.get('category', ''),
            engine=record.get('engine', ''),
            action=record.get('action', ''),
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _id=self.id, _name=self.name, _builtin=self.builtin,
                    _category=self.category)


@dataclass
class ModelGroup:
    id: str
    name: str
    strategy: str
    models: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_api(cls, record: dict) -> 'ModelGroup':
        models = []
        for member in record.get('members') or []:
            model = (member or {}).get('model') or {}
            public = model.get('publicName') or model.get('modelId')
            if public:
                models.append(public)
        return cls(
            id=record.get('id', ''),
            name=record.get('name', ''),
            strategy=record.get('strategy', ''),
            models=sorted(set(models)),
            raw=record,
        )

    def to_dict(self) -> dict:
        return dict(self.raw, _id=self.id, _name=self.name,
                    _strategy=self.strategy, _models=self.models)


class FaigClient:
    """Session-managed client for the FortiAIGate management + data plane API."""

    def __init__(self, server: str, username: str, password: str,
                 verify_ssl: bool = True, data_plane_base: Optional[str] = None,
                 timeout: int = 30, workspace: Optional[str] = None):
        self.server = normalize_server(server)
        self.workspace = (workspace or '').strip() or None
        self.username = username
        self.password = password
        self.verify_ssl = bool(verify_ssl)
        dp = (data_plane_base or '').strip().rstrip('/')
        self.data_plane_base = dp if dp else self.server
        self.timeout = int(timeout or 30)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        self._csrf: Optional[str] = None
        self._logged_in = False
        self._role: Optional[str] = None
        self._default_ws: Optional[str] = None

    # - low level ------------------------------------------------------------

    def _url(self, path: str) -> str:
        return self.server + path

    def _login(self) -> None:
        resp = self.session.post(
            self._url('/api/v1/login'),
            json={'username': self.username, 'password': self.password},
            timeout=self.timeout)
        if resp.status_code != 200:
            raise ConnectorError(
                'FortiAIGate login failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:200]))
        body = resp.json()
        self._csrf = body.get('csrf_token')
        self._logged_in = True
        logger.info('Logged in to FortiAIGate as {0}'.format(self.username))

    def _fresh_csrf(self) -> str:
        resp = self.session.get(self._url('/api/csrf-token'),
                                timeout=self.timeout)
        if resp.status_code != 200:
            raise ConnectorError(
                'Could not obtain CSRF token (HTTP {0})'.format(resp.status_code))
        return resp.json().get('csrf_token', '')

    def _request(self, method: str, path: str, json_body: Any = None,
                 retry_auth: bool = True,
                 params: Any = None, follow_redirects: bool = True) -> requests.Response:
        if not self._logged_in:
            self._login()
        headers = {}
        if method != 'GET':
            headers['X-CSRF-Token'] = self._fresh_csrf()
            # The JSON API rejects bodiless mutations ("request body is
            # required") even where the console sends an empty object.
            if json_body is None:
                json_body = {}
        resp = self.session.request(method, self._url(path),
                                    json=json_body, headers=headers,
                                    params=params,
                                    timeout=self.timeout,
                                    allow_redirects=follow_redirects)
        if resp.status_code == 401 and retry_auth:
            self._logged_in = False
            return self._request(method, path, json_body, retry_auth=False,
                                 params=params, follow_redirects=follow_redirects)
        return resp

    def _call(self, method: str, path: str, json_body: Any = None,
              params: Any = None, follow_redirects: bool = True) -> Any:
        resp = self._request(method, path, json_body, params=params,
                             follow_redirects=follow_redirects)
        if not follow_redirects and 300 <= resp.status_code < 400:
            # The session cookie and CSRF token must not follow a redirect to another host.
            raise ConnectorError('FortiAIGate answered with a redirect (HTTP {0}); not following '
                                 'it so the session stays on the configured server'.format(resp.status_code))
        if resp.status_code == 403 and ORG_ONLY in resp.text:
            raise ConnectorError(
                'FortiAIGate {0} {1} needs an organization administrator, and {2} is a {3} '
                'login. Operations on keys, guardrails, policies, detectors and logs work in '
                'your workspace; this one does not.'.format(
                    method, path, self.username, self._role or 'workspace'))
        if resp.status_code >= 400:
            raise ConnectorError(
                'FortiAIGate API {0} {1} failed (HTTP {2}): {3}'.format(
                    method, path, resp.status_code, resp.text[:300]))
        if not resp.content:
            return {}
        return resp.json()

    def raw(self, method: str, endpoint: str, params: Any = None, body: Any = None) -> Any:
        """Any management API call, with this client's session and CSRF handling."""
        return self._call(method, safe_endpoint(endpoint), json_body=body, params=params,
                          follow_redirects=False)

    # - scope ----------------------------------------------------------------

    def me(self) -> dict:
        """The logged-in user: ``role`` and ``memberships`` among others."""
        data = self._call('GET', '/api/v1/user')
        return data if isinstance(data, dict) else {}

    @property
    def role(self) -> str:
        if self._role is None:
            self._role = str(self.me().get('role') or '')
        return self._role

    @property
    def org_scope(self) -> bool:
        """True for an organization administrator (the /api/v1/admin paths);
        False for a workspace login, whose calls go to its workspace."""
        return self.role in ORG_ROLES

    def default_workspace(self) -> str:
        """The workspace id a workspace login acts in: the configured
        Workspace (name or id) when set, else its only membership."""
        if self._default_ws:
            return self._default_ws
        mine = [(w.get('_id'), w.get('_workspaceName')) for w in self.list_my_workspaces()]
        if self.workspace:
            found = [wid for wid, name in mine if self.workspace in (wid, name)]
            if not found:
                raise ConnectorError(
                    '{0} is not a member of a workspace named "{1}". Its workspaces: {2}'.format(
                        self.username, self.workspace, ', '.join(n for _, n in mine) or 'none'))
            self._default_ws = found[0]
        elif len(mine) == 1:
            self._default_ws = mine[0][0]
        else:
            raise ConnectorError(
                '{0} is a member of {1} workspaces ({2}); set Workspace in the connector '
                'configuration, or pass the workspace to this action.'.format(
                    self.username, len(mine), ', '.join(n for _, n in mine) or 'none'))
        return self._default_ws

    def _path(self, suffix: str, workspace_id: Optional[str] = None) -> str:
        """``/api/v1/admin/<suffix>`` for an org admin, otherwise the same
        resource in a workspace (``workspace_id`` or the default one)."""
        if self.org_scope:
            return '/api/v1/admin/' + suffix
        return '/api/v1/workspaces/{0}/{1}'.format(_seg(workspace_id or self.default_workspace()), suffix)

    # - management API ------------------------------------------------------

    def list_workspaces(self) -> list:
        if not self.org_scope:
            return self.list_my_workspaces()
        data = self._call('GET', '/api/v1/admin/workspaces')
        items = data if isinstance(data, list) else data.get('items', data.get('workspaces', []))
        return [Workspace.from_api(item).to_dict() for item in items]

    def list_my_workspaces(self) -> list:
        """Workspaces the logged-in admin is a member of. Key creation
        requires the key owner to be a member of the target workspace."""
        data = self._call('GET', '/api/v1/me/workspaces')
        items = data if isinstance(data, list) else data.get('items', data.get('workspaces', []))
        return [Workspace.from_api(item).to_dict() for item in items]

    def list_virtual_keys(self, workspace_id: Optional[str] = None,
                          status: Optional[str] = None) -> list:
        data = self._call('GET', self._path('virtual-keys', None if self.org_scope else workspace_id))
        keys = data if isinstance(data, list) else data.get('items', [])
        result = []
        for record in keys:
            if workspace_id:
                ws = record.get('workspace')
                ws_id = ws.get('id') if isinstance(ws, dict) else ws
                if ws_id != workspace_id and record.get('workspaceId') != workspace_id:
                    continue
            if status and record.get('status') != status:
                continue
            result.append(VirtualKey.from_api(record).to_dict())
        return result

    def get_virtual_key(self, key_id: str) -> dict:
        data = self._call('GET', self._path('virtual-keys/{0}'.format(_seg(key_id))))
        record = data.get('key', data) if isinstance(data, dict) else {}
        if not isinstance(record, dict) or 'id' not in record:
            raise ConnectorError(
                'Unexpected virtual key response for {0}: {1}'.format(
                    key_id, str(data)[:200]))
        return VirtualKey.from_api(record).to_dict()

    def create_virtual_key(self, workspace_id: str, key_name: str,
                           expires_at: Optional[str] = None,
                           tpm: Optional[str] = None,
                           rpm: Optional[str] = None,
                           provider_ids: Optional[list] = None) -> dict:
        body: dict = {'keyName': key_name}
        if provider_ids:
            # 8.0.2 refuses a key with no model access (422 "At least one model or model
            # group is required"); this grants every model of each provider.
            body['providerAccess'] = [{'providerId': str(p), 'allKeys': True, 'allModels': True}
                                      for p in provider_ids]
        if expires_at:
            body['expiresAt'] = expires_at
        if tpm:
            body['tpm'] = tpm
        if rpm:
            body['rpm'] = rpm
        # Always the workspace route: on 8.0.2 the org-admin route
        # (/api/v1/admin/virtual-keys + workspaceId) answers 404 "the key owner is
        # not a member of this workspace" even for a member.
        ws = workspace_id or (None if self.org_scope else self.default_workspace())
        if not ws:
            raise ConnectorError('Workspace ID is required to create a key')
        return self._with_secret(
            self._call('POST', '/api/v1/workspaces/{0}/virtual-keys'.format(_seg(ws)), body))

    @staticmethod
    def _with_secret(data):
        """Copy the once-only secret to new_secret, whichever field the gateway used."""
        if isinstance(data, dict) and 'new_secret' not in data:
            for candidate in SECRET_RESPONSE_FIELDS:
                value = data.get(candidate)
                if isinstance(value, str) and value.startswith('faig_'):
                    data['new_secret'] = value
                    break
        return data

    def update_virtual_key(self, key_id: str,
                           expires_at: Optional[str] = None,
                           tpm: Optional[str] = None,
                           rpm: Optional[str] = None,
                           policy_ids: Optional[list] = None) -> dict:
        """Merge-supplied update: the API replaces the full record, so read
        the current one first and resend its writable fields plus the changes
        (8.0.2 answers 422 to read-only fields such as ``status`` or
        ``updatedAt``, and to policies sent as objects). ``policy_ids``
        REPLACES the key's own policies; org-assigned ones are always sent
        back, since leaving one out reads as detaching it (org admin only)."""
        current = self._call('GET', self._path('virtual-keys/{0}'.format(_seg(key_id))))
        record = current.get('key', current) if isinstance(current, dict) else {}
        body = {k: record[k] for k in KEY_WRITABLE if k in record}
        policies = record.get('policyIds') or []
        body['policyIds'] = [str(p['id']) if isinstance(p, dict) else str(p) for p in policies]
        for target, value in (('expiresAt', expires_at), ('tpm', tpm),
                              ('rpm', rpm)):
            if value:
                body[target] = value
        if policy_ids:
            org = [str(p['id']) for p in policies if isinstance(p, dict) and p.get('assignedByOrg')]
            body['policyIds'] = list(dict.fromkeys(org + [str(p) for p in policy_ids]))
        return self._call('PUT', self._path('virtual-keys/{0}'.format(_seg(key_id))), body)

    def rotate_virtual_key(self, key_id: str) -> dict:
        return self._with_secret(
            self._call('POST', self._path('virtual-keys/{0}/rotate'.format(_seg(key_id)))))

    def revoke_virtual_key(self, key_id: str, reason: str = 'Revoked from FortiSOAR') -> dict:
        # The gateway rejects a revoke without a reason ("expected required property reason").
        return self._call('POST', self._path('virtual-keys/{0}/revoke'.format(_seg(key_id))),
                          json_body={'reason': reason})

    # - data plane ---------------------------------------------------------

    def check_key(self, api_key: str,
                  data_plane_base: Optional[str] = None) -> dict:
        """Probe the OpenAI-compatible models endpoint with a key secret.

        Returns ``valid=True`` plus the model count for a working key, or
        ``valid=False`` with the HTTP status for a rejected one. Only
        transport-level failures raise.
        """
        base = (data_plane_base or '').strip().rstrip('/') or self.data_plane_base
        try:
            resp = self.session.get(
                base + '/ai/openai/v1/models',
                headers={'Authorization': 'Bearer {0}'.format(api_key)},
                timeout=self.timeout)
        except requests.RequestException as err:
            raise ConnectorError('Data plane request failed: {0}'.format(err))
        if resp.status_code == 200:
            body = resp.json()
            model_count = len(body.get('data', [])) if isinstance(body, dict) else 0
            return {'valid': True, 'model_count': model_count, 'http_status': 200}
        if resp.status_code in (401, 403):
            return {'valid': False, 'model_count': 0, 'http_status': resp.status_code}
        raise ConnectorError(
            'Data plane returned HTTP {0}: {1}'.format(resp.status_code, resp.text[:200]))

    # - governance: policies, guardrails, providers, budget, audit -----------

    def list_policies(self, workspace_id: Optional[str] = None) -> list:
        if not self.org_scope:
            records = self._call('GET', self._path('policies', workspace_id))
            return [Policy.from_api(p).to_dict()
                    for p in (records if isinstance(records, list) else records.get('items', []))]
        records = self._call('GET', '/api/v1/admin/policies')
        policies = records if isinstance(records, list) else records.get('items', [])
        if workspace_id:
            scoped = self._call(
                'GET', '/api/v1/workspaces/{0}/policies'.format(_seg(workspace_id)))
            if isinstance(scoped, list):
                policies = policies + scoped
        return [Policy.from_api(p).to_dict() for p in policies]

    def get_policy(self, policy_id: str) -> dict:
        data = self._call('GET', self._path('policies/{0}'.format(_seg(policy_id))))
        record = data.get('policy', data) if isinstance(data, dict) else {}
        if 'id' not in record:
            raise ConnectorError(
                'Unexpected policy response for {0}'.format(policy_id))
        return Policy.from_api(record).to_dict()

    def list_guardrails(self) -> list:
        records = self._call('GET', self._path('guardrails'))
        guardrails = records if isinstance(records, list) else records.get('items', [])
        return [Guardrail.from_api(g).to_dict() for g in guardrails]

    def get_guardrail(self, guardrail_id: str) -> dict:
        data = self._call('GET', self._path('guardrails/{0}'.format(_seg(guardrail_id))))
        record = data.get('guardrail', data) if isinstance(data, dict) else {}
        if 'id' not in record:
            raise ConnectorError(
                'Unexpected guardrail response for {0}'.format(guardrail_id))
        return Guardrail.from_api(record).to_dict()

    def test_guardrail(self, input_text: str, detector_ids: Optional[list] = None,
                       guardrail_id: Optional[str] = None,
                       deny_suspicious_characters: bool = False) -> dict:
        """Scan text through the gateway's guardrail scanner (no LLM involved).

        Either pass detector ids directly, or a guardrail id to reuse its
        detectors and its denySuspiciousCharacters setting.
        """
        if not detector_ids and not guardrail_id:
            raise ConnectorError('detector_ids or guardrail_id is required')
        if guardrail_id and not detector_ids:
            record = self.get_guardrail(guardrail_id)
            detector_ids = record.get('detectorIds') or record.get('_detectorIds') or []
            deny_suspicious_characters = bool(
                record.get('denySuspiciousCharacters', deny_suspicious_characters))
        body = {'input': input_text,
                'detectorIds': detector_ids,
                'denySuspiciousCharacters': bool(deny_suspicious_characters)}
        path = self._path('guardrails/test')
        resp = self._request('POST', path, body)
        if resp.status_code not in (404, 405):
            if resp.status_code >= 400:
                raise ConnectorError('FortiAIGate API POST {0} failed (HTTP {1}): {2}'.format(
                    path, resp.status_code, resp.text[:300]))
            return GuardrailTestResult.from_api(resp.json()).to_dict()
        # No guardrail tester here (a workspace login on 8.0.2 gets 405): scan with each
        # saved custom detector instead. A built-in detector has no offline test on such a
        # build, so its row says "untested"; only a request through the gateway shows it.
        results = []
        for detector_id in detector_ids:
            if not UUID_RE.match(str(detector_id)):
                results.append({'detectorId': detector_id, 'status': 'untested', 'matched': False,
                                'finalDisposition': None,
                                'details': 'built-in detector: no offline test on this FortiAIGate; '
                                           'send the text through the gateway (Chat Completion)'})
                continue
            one = self._call('POST', self._path('detectors/{0}/test'.format(_seg(detector_id))),
                             {'input': input_text})
            results.append(dict(one, detectorId=detector_id, status='tested'))
        verdicts = [r.get('finalDisposition') for r in results if r.get('matched')]
        final = max(verdicts, key=lambda d: DISPOSITION_RANK.get(d, 0)) if verdicts else 'allow'
        return GuardrailTestResult.from_api({
            'results': results, 'finalDisposition': final, 'scannedChars': len(input_text),
            'untested': [r['detectorId'] for r in results if r['status'] == 'untested']}).to_dict()

    def list_ai_providers(self) -> list:
        if not self.org_scope:
            raise ConnectorError(
                'Listing AI providers needs an organization administrator; {0} is a {1} login. '
                'List Policies shows the providers your workspace may use.'.format(self.username, self.role))
        records = self._call('GET', '/api/v1/admin/ai-providers')
        providers = records if isinstance(records, list) else records.get('items', [])
        return [AiProvider.from_api(p).to_dict() for p in providers]

    def list_custom_detectors(self) -> list:
        """Custom detectors: identified by uuid, name, scope, engine."""
        records = self._call('GET', self._path('detectors'))
        items = records if isinstance(records, list) else records.get('items', [])
        return [Detector.from_custom(d).to_dict() for d in items]

    def list_builtin_detectors(self) -> list:
        """Built-in detectors: identified by a slug id, with a category."""
        records = self._call('GET', self._path('built-in-detectors'))
        items = records if isinstance(records, list) else records.get('items', [])
        return [Detector.from_builtin(d).to_dict() for d in items]

    def list_model_groups(self) -> list:
        """Org model groups: id, name, strategy, and member model public
        names (the identifier chat completions accept as ``model``)."""
        path = '/api/v1/model-groups' if self.org_scope else self._path('model-groups')
        records = self._call('GET', path)
        items = records if isinstance(records, list) else records.get('items', [])
        return [ModelGroup.from_api(g).to_dict() for g in items]

    def get_workspace_budget(self, workspace_id: str) -> dict:
        data = self._call('GET', '/api/v1/workspaces/{0}/budget'.format(_seg(workspace_id)))
        if not isinstance(data, dict):
            raise ConnectorError(
                'Unexpected budget response for {0}'.format(_seg(workspace_id)))
        return dict(data, workspaceId=workspace_id)

    def list_audit_logs(self, offset: int = 0, limit: int = 25) -> dict:
        params = {'offset': str(int(offset)), 'limit': str(int(limit))}
        resp = self._request('GET', self._path('audit-logs'), params=params)
        if resp.status_code >= 400:
            raise ConnectorError(
                'FortiAIGate audit-logs failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:200]))
        return resp.json()

    def get_audit_log_filter_options(self) -> dict:
        return self._call('GET', self._path('audit-logs/filter-options'))

    # - data plane ---------------------------------------------------------

    def chat_completion(self, api_key: str, model: str, messages: list,
                        max_tokens: Optional[int] = None,
                        temperature: Optional[float] = None,
                        data_plane_base: Optional[str] = None) -> dict:
        """One OpenAI-compatible chat completion through the gateway.

        Guardrails and policies attached to the key's workspace apply, so
        playbook AI steps inherit the gateway's enforcement for free.
        """
        base = (data_plane_base or '').strip().rstrip('/') or self.data_plane_base
        if not isinstance(messages, (list, tuple)) or not messages:
            raise ConnectorError('messages must be a list of chat messages')
        body: dict = {'model': model, 'messages': list(messages), 'stream': False}
        if max_tokens:
            body['max_tokens'] = int(max_tokens)
        if temperature is not None and temperature != '':
            body['temperature'] = float(temperature)
        try:
            resp = self.session.post(
                base + '/ai/openai/v1/chat/completions',
                json=body,
                headers={'Authorization': 'Bearer {0}'.format(api_key)},
                timeout=max(self.timeout, 120))
        except requests.RequestException as err:
            raise ConnectorError('Data plane request failed: {0}'.format(err))
        if resp.status_code != 200:
            raise ConnectorError(
                'Chat completion failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:300]))
        return ChatResult.from_response(resp.json()).to_dict()

    def health(self) -> str:
        """Log in and settle the scope. A workspace login must resolve its
        workspace now (a wrong Workspace name fails here, not mid-playbook);
        one in several workspaces with none configured still passes, since
        each action can name its workspace."""
        self._login()
        if not self.org_scope and (self.workspace or len(self.list_my_workspaces()) == 1):
            self.default_workspace()
        return 'ok'
