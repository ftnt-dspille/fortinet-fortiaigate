"""Typed FortiAIGate management client used by the connector operations.

Talks to the FortiAIGate 8.x admin console JSON API:

- ``POST /api/v1/login`` with username/password returns a session cookie
  plus a first CSRF token.
- Every mutating method (POST/PUT/PATCH/DELETE) must send a fresh
  ``X-CSRF-Token`` header, obtained per mutation from ``GET /api/csrf-token``.
- Virtual keys live under ``/api/v1/admin/virtual-keys``; their *secret* is
  returned exactly once, at create/rotate time, and never readable again.
- The data plane is the OpenAI-compatible gateway under
  ``{data_plane_base}/ai/openai/v1``; a virtual key is valid there while its
  record is active and unexpired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('fortinet-fortiaigate')

SECRET_RESPONSE_FIELDS = (
    'secretKey', 'secret_key', 'apiKey', 'api_key', 'newKey', 'new_key', 'key',
)


def key_id_from_secret(api_key: str) -> str:
    """A virtual key secret embeds its record id: faig_<uuid-no-dashes>_...

    The id is recovered from the secret by re-inserting the UUID dashes,
    so callers that hold the secret do not need to look the record up.
    """
    bare = api_key.split('_')[1]
    return '-'.join((bare[:8], bare[8:12], bare[12:16], bare[16:20], bare[20:]))


def normalize_server(server: str) -> str:
    server = (server or '').strip().rstrip('/')
    if not server:
        raise ConnectorError('Server URL is required')
    if not (server.startswith('http://') or server.startswith('https://')):
        server = 'https://' + server
    return server


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
                 timeout: int = 30):
        self.server = normalize_server(server)
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
                 params: Any = None) -> requests.Response:
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
                                    timeout=self.timeout)
        if resp.status_code == 401 and retry_auth:
            self._logged_in = False
            return self._request(method, path, json_body, retry_auth=False)
        return resp

    def _call(self, method: str, path: str, json_body: Any = None) -> Any:
        resp = self._request(method, path, json_body)
        if resp.status_code >= 400:
            raise ConnectorError(
                'FortiAIGate API {0} {1} failed (HTTP {2}): {3}'.format(
                    method, path, resp.status_code, resp.text[:300]))
        if not resp.content:
            return {}
        return resp.json()

    # - management API ------------------------------------------------------

    def list_workspaces(self) -> list:
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
        data = self._call('GET', '/api/v1/admin/virtual-keys')
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
        data = self._call('GET', '/api/v1/admin/virtual-keys/{0}'.format(key_id))
        record = data.get('key', data) if isinstance(data, dict) else {}
        if not isinstance(record, dict) or 'id' not in record:
            raise ConnectorError(
                'Unexpected virtual key response for {0}: {1}'.format(
                    key_id, str(data)[:200]))
        return VirtualKey.from_api(record).to_dict()

    def create_virtual_key(self, workspace_id: str, key_name: str,
                           expires_at: Optional[str] = None,
                           tpm: Optional[str] = None,
                           rpm: Optional[str] = None) -> dict:
        body: dict = {'workspaceId': workspace_id, 'keyName': key_name}
        if expires_at:
            body['expiresAt'] = expires_at
        if tpm:
            body['tpm'] = tpm
        if rpm:
            body['rpm'] = rpm
        return self._call('POST', '/api/v1/admin/virtual-keys', body)

    def update_virtual_key(self, key_id: str,
                           expires_at: Optional[str] = None,
                           tpm: Optional[str] = None,
                           rpm: Optional[str] = None,
                           policy_ids: Optional[list] = None) -> dict:
        """Merge-supplied update: the API replaces the full record, so read
        the current one first and resend its fields plus the changes.
        ``policy_ids`` REPLACES the attached policy list (org-assigned
        policies stay forced onto the key regardless)."""
        current = self._call('GET', '/api/v1/admin/virtual-keys/{0}'.format(key_id))
        record = current.get('key', current) if isinstance(current, dict) else {}
        body = dict(record)
        body.pop('id', None)
        for target, value in (('expiresAt', expires_at), ('tpm', tpm),
                              ('rpm', rpm)):
            if value:
                body[target] = value
        if policy_ids:
            body['policyIds'] = [str(p) for p in policy_ids]
        return self._call('PUT', '/api/v1/admin/virtual-keys/{0}'.format(key_id), body)

    def rotate_virtual_key(self, key_id: str) -> dict:
        data = self._call('POST', '/api/v1/admin/virtual-keys/{0}/rotate'.format(key_id))
        if isinstance(data, dict) and 'new_secret' not in data:
            for candidate in SECRET_RESPONSE_FIELDS:
                value = data.get(candidate)
                if isinstance(value, str) and value.startswith('faig_'):
                    data['new_secret'] = value
                    break
        return data

    def revoke_virtual_key(self, key_id: str) -> dict:
        return self._call('POST', '/api/v1/admin/virtual-keys/{0}/revoke'.format(key_id))

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
        records = self._call('GET', '/api/v1/admin/policies')
        policies = records if isinstance(records, list) else records.get('items', [])
        if workspace_id:
            scoped = self._call(
                'GET', '/api/v1/workspaces/{0}/policies'.format(workspace_id))
            if isinstance(scoped, list):
                policies = policies + scoped
        return [Policy.from_api(p).to_dict() for p in policies]

    def get_policy(self, policy_id: str) -> dict:
        data = self._call('GET', '/api/v1/admin/policies/{0}'.format(policy_id))
        record = data.get('policy', data) if isinstance(data, dict) else {}
        if 'id' not in record:
            raise ConnectorError(
                'Unexpected policy response for {0}'.format(policy_id))
        return Policy.from_api(record).to_dict()

    def list_guardrails(self) -> list:
        records = self._call('GET', '/api/v1/admin/guardrails')
        guardrails = records if isinstance(records, list) else records.get('items', [])
        return [Guardrail.from_api(g).to_dict() for g in guardrails]

    def get_guardrail(self, guardrail_id: str) -> dict:
        data = self._call('GET', '/api/v1/admin/guardrails/{0}'.format(guardrail_id))
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
        data = self._call('POST', '/api/v1/admin/guardrails/test', body)
        return GuardrailTestResult.from_api(data).to_dict()

    def list_ai_providers(self) -> list:
        records = self._call('GET', '/api/v1/admin/ai-providers')
        providers = records if isinstance(records, list) else records.get('items', [])
        return [AiProvider.from_api(p).to_dict() for p in providers]

    def list_custom_detectors(self) -> list:
        """Custom detectors: identified by uuid, name, scope, engine."""
        records = self._call('GET', '/api/v1/admin/detectors')
        items = records if isinstance(records, list) else records.get('items', [])
        return [Detector.from_custom(d).to_dict() for d in items]

    def list_builtin_detectors(self) -> list:
        """Built-in detectors: identified by a slug id, with a category."""
        records = self._call('GET', '/api/v1/admin/built-in-detectors')
        items = records if isinstance(records, list) else records.get('items', [])
        return [Detector.from_builtin(d).to_dict() for d in items]

    def list_model_groups(self) -> list:
        """Org model groups: id, name, strategy, and member model public
        names (the identifier chat completions accept as ``model``)."""
        records = self._call('GET', '/api/v1/model-groups')
        items = records if isinstance(records, list) else records.get('items', [])
        return [ModelGroup.from_api(g).to_dict() for g in items]

    def get_workspace_budget(self, workspace_id: str) -> dict:
        data = self._call('GET', '/api/v1/workspaces/{0}/budget'.format(workspace_id))
        if not isinstance(data, dict):
            raise ConnectorError(
                'Unexpected budget response for {0}'.format(workspace_id))
        return dict(data, workspaceId=workspace_id)

    def list_audit_logs(self, offset: int = 0, limit: int = 25) -> dict:
        params = {'offset': str(int(offset)), 'limit': str(int(limit))}
        resp = self._request('GET', '/api/v1/admin/audit-logs', params=params)
        if resp.status_code >= 400:
            raise ConnectorError(
                'FortiAIGate audit-logs failed (HTTP {0}): {1}'.format(
                    resp.status_code, resp.text[:200]))
        return resp.json()

    def get_audit_log_filter_options(self) -> dict:
        return self._call('GET', '/api/v1/admin/audit-logs/filter-options')

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
        self._login()
        return 'ok'
