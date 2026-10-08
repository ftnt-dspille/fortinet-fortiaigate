"""Test fixtures for the FortiAIGate connector.

- Stubs the FortiSOAR connector SDK so the connector imports standalone
  (no appliance, no ``cs-smart-connectors`` package needed).
- Registers the hyphenated connector directory as the importable virtual
  package ``fortiaigate``.
- Serves a ``FakeFortiAIGate`` gateway on a loopback ephemeral port, using
  only the standard library: it enforces the cookie session, per-mutation
  CSRF, one-time key secrets, and the data-plane models probe.
"""

from __future__ import annotations

import json
import sys
import threading
import types
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

CONNECTOR_DIR = Path(__file__).resolve().parent.parent

# --- stub the FortiSOAR SDK so the connector imports standalone ----------
if "connectors" not in sys.modules:
    _connectors = types.ModuleType("connectors")
    _connectors.__path__ = []
    _core = types.ModuleType("connectors.core")
    _core.__path__ = []
    _connector_mod = types.ModuleType("connectors.core.connector")

    class ConnectorError(Exception):
        pass

    import logging

    def get_logger(name):
        return logging.getLogger(name)

    class Connector:
        pass

    _connector_mod.ConnectorError = ConnectorError
    _connector_mod.get_logger = get_logger
    _connector_mod.Connector = Connector
    _core.connector = _connector_mod
    _connectors.core = _core
    sys.modules["connectors"] = _connectors
    sys.modules["connectors.core"] = _core
    sys.modules["connectors.core.connector"] = _connector_mod

# --- make the hyphenated dir importable as the 'fortiaigate' package ------
if "fortiaigate" not in sys.modules:
    _pkg = types.ModuleType("fortiaigate")
    _pkg.__path__ = [str(CONNECTOR_DIR)]
    sys.modules["fortiaigate"] = _pkg

from fortiaigate.connections import FaigClient  # noqa: E402

GOOD_KEY = 'faig_good123_secret'


class FakeState:
    """What the fake gateway knows, plus the last captured request bodies."""

    def __init__(self):
        self.port = 0
        self.reset()

    def reset(self):
        self.username = 'admin@example.com'
        self.password = 'correct-password'
        self.session_valid = False
        self.workspaces = [
            {'id': 'ws-1', 'workspaceName': 'Default', 'memberCount': 1},
            {'id': 'ws-2', 'workspaceName': 'Research', 'memberCount': 2},
        ]
        self.keys = {
            'k-1': {'id': 'k-1', 'keyName': 'alpha', 'status': 'active',
                    'expiresAt': None, 'keyPreview': 'faig-AAA-k-1'},
            'k-2': {'id': 'k-2', 'keyName': 'beta', 'status': 'revoked',
                    'expiresAt': '2026-01-01T00:00:00.000Z', 'keyPreview': 'faig-BBB-k-2'},
            # rotates by api_key derive this record id from the secret
            '9f8e7d6c-5b4a-3928-1706-f1e2d3c4b5a6': {
                'id': '9f8e7d6c-5b4a-3928-1706-f1e2d3c4b5a6', 'keyName': 'gamma',
                'status': 'active', 'expiresAt': '2026-02-02T00:00:00.000Z',
                'keyPreview': 'faig-CCC'},
        }
        self.policies = [
            {'id': 'pol-1', 'name': 'owasp-guard', 'status': 'active',
             'inputGuardrailIds': ['gr-1'], 'outputGuardrailIds': ['gr-1'],
             'providerAccess': [{'providerId': 'openai'}],
             'applyToOrganization': False, 'assignedWorkspaceIds': ['ws-1'],
             'responseScanMode': 'post_stream'},
            {'id': 'pol-2', 'name': 'dlp', 'status': 'pending',
             'inputGuardrailIds': ['gr-2'], 'outputGuardrailIds': [],
             'providerAccess': [], 'applyToOrganization': True,
             'assignedWorkspaceIds': [], 'responseScanMode': 'in_stream',
             'hasPendingChange': True, 'pendingChangeKind': 'edit'},
        ]
        self.guardrails = {
            'gr-1': {'id': 'gr-1', 'name': 'general-owasp-guardrail',
                     'detectorIds': ['det-owasp'], 'denySuspiciousCharacters': False,
                     'status': 'active', 'usedByPolicyCount': 1},
            'gr-2': {'id': 'gr-2', 'name': 'dlp-guard', 'detectorIds': ['det-dlp'],
                     'denySuspiciousCharacters': True, 'status': 'active',
                     'usedByPolicyCount': 1},
        }
        self.providers = [
            {'providerId': 'openai', 'label': 'OpenAI', 'description': '',
             'baseUrl': 'https://api.openai.com', 'platform': 'openai',
             'modelCount': 80, 'enabledModelCount': 80, 'keyCount': 2},
        ]
        self.custom_detectors = [
            {'uuid': 'cut-1', 'name': 'Prompt Injection Detector', 'scope': 'workspace',
             'engine': 'rules', 'action': 'block', 'approvalStatus': 'approved'},
        ]
        self.builtin_detectors = [
            {'id': 'owasp-agentic-top-10', 'name': 'OWASP Agentic Top 10',
             'category': 'security', 'engine': 'rules', 'action': 'block'},
            {'id': 'gdpr', 'name': 'GDPR', 'category': 'privacy',
             'engine': 'rules', 'action': 'block'},
        ]
        self.model_groups = [
            {'id': 'mg-1', 'name': 'default-group', 'strategy': 'random',
             'members': [
                 {'model': {'publicName': 'openai-test-mini', 'modelId': 'test-mini',
                            'providerId': 'openai', 'uuid': 'm-1'}, 'status': 'active'},
                 {'model': {'publicName': 'anthropic-test-haiku', 'modelId': 'test-haiku',
                            'providerId': 'anthropic', 'uuid': 'm-2'}, 'status': 'active'},
             ]},
        ]
        self.audit_events = [
            {'uuid': 'e-{0}'.format(i), 'action': 'login_user' if i % 3 else 'update',
             'actionLabel': 'Login', 'message': 'user logged in', 'role': 'org_admin',
             'sourceIp': '10.0.0.{0}'.format(i % 250), 'timeStamp': '2026-10-08T10:{0:02d}:00Z'.format(i),
             'type': 'admin', 'username': 'admin@example.com', 'workspace': None}
            for i in range(12)
        ]
        self.last_guardrail_test = None
        self.last_put_body = None
        self.mutations = 0
        self.expire_after_mutations = None


STATE = FakeState()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body, cookie=None):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        if cookie:
            self.send_header('Set-Cookie', 'session_id={0}; Path=/'.format(cookie))
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _body(self):
        length = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(length)) if length else {}

    def _sessioned(self):
        return STATE.session_valid

    def do_POST(self):
        if self.path == '/api/v1/login':
            body = self._body()
            if (body.get('username') == STATE.username
                    and body.get('password') == STATE.password):
                STATE.session_valid = True
                STATE.mutations = 0
                self._send(200, {'csrf_token': 'login-token', 'role': 'admin'},
                           cookie='sess123')
            else:
                self._send(401, {'error': 'Incorrect username or password'})
            return
        if self.path == '/ai/openai/v1/chat/completions':
            # data plane: Bearer-authenticated, no session/CSRF
            if self.headers.get('Authorization') != 'Bearer ' + GOOD_KEY:
                self._send(401, {'error': {'message': 'invalid key'}})
                return
            body = self._body()
            self._send(200, {
                'id': 'chatcmpl-test', 'object': 'chat.completion',
                'created': 1790000000,
                'model': body.get('model', ''),
                'choices': [{'index': 0, 'finish_reason': 'stop',
                             'message': {'role': 'assistant', 'content': 'OK'},
                             'logprobs': None}],
                'usage': {'prompt_tokens': 5, 'completion_tokens': 1,
                          'total_tokens': 6},
                'service_tier': 'default', 'system_fingerprint': 'fp-test'})
            return
        if not self._sessioned():
            self._send(401, {'error': 'no session'})
            return
        if not self.headers.get('X-CSRF-Token'):
            self._send(403, {'error': 'missing csrf'})
            return
        if self.path == '/api/v1/admin/virtual-keys':
            body = self._body()
            new_id = 'k-' + uuid.uuid4().hex[:8]
            record = {'id': new_id, 'keyName': body.get('keyName', ''),
                      'status': 'active', 'expiresAt': body.get('expiresAt'),
                      'tpm': body.get('tpm'), 'rpm': body.get('rpm'),
                      'keyPreview': 'faig-' + new_id[:4]}
            secret = 'faig_' + uuid.uuid4().hex[:24]
            STATE.keys[new_id] = record
            self._send(200, dict(record, secretKey=secret))
            return
        key_id = self._key_id_from('/api/v1/admin/virtual-keys/', '/rotate')
        if key_id and key_id in STATE.keys:
            STATE.keys[key_id]['status'] = 'active'
            self._send(200, {'id': key_id,
                             'secretKey': 'faig_rotated_' + uuid.uuid4().hex[:12]})
            return
        if self.path == '/api/v1/admin/guardrails/test':
            body = self._body()
            STATE.last_guardrail_test = body
            input_text = body.get('input', '')
            detector_ids = body.get('detectorIds') or []
            results = []
            for det in detector_ids:
                matched = det == 'det-owasp' and 'ignore all previous' in input_text
                results.append({'detectorId': det, 'status': 'completed',
                                 'matched': matched,
                                 'finalDisposition': 'block' if matched else 'allow',
                                 'score': 0.99 if matched else 0.01,
                                 'details': 'Rules violated: test detector' if matched else '',
                                 'spans': []})
            any_matched = any(r['matched'] for r in results)
            self._send(200, {'results': results,
                             'finalDisposition': 'block' if any_matched else 'allow',
                             'rewritten': input_text, 'latencyMs': 3,
                             'scannedChars': len(input_text),
                             'suspiciousCharacters': False, 'truncated': False,
                             'decoding': 'utf-8'})
            return
        key_id = self._key_id_from('/api/v1/admin/virtual-keys/', '/revoke')
        if key_id and key_id in STATE.keys:
            STATE.keys[key_id]['status'] = 'revoked'
            self._send(200, {'id': key_id, 'status': 'revoked'})
            return
        self._send(404, {'error': 'not found'})

    def do_GET(self):
        if self.path == '/api/csrf-token':
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
            else:
                self._send(200, {'csrf_token': 'fresh'})
            return
        if self.path == '/api/v1/admin/workspaces':
            if self._sessioned():
                self._send(200, STATE.workspaces)
            else:
                self._send(401, {'error': 'no session'})
            return
        if self.path == '/api/v1/me/workspaces':
            if self._sessioned():
                self._send(200, STATE.workspaces[:1])
            else:
                self._send(401, {'error': 'no session'})
            return
        if self.path == '/api/v1/admin/virtual-keys':
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            self._send(200, list(STATE.keys.values()))
            return
        key_id = self._key_id_from('/api/v1/admin/virtual-keys/', '')
        if key_id:
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
            elif key_id in STATE.keys:
                self._send(200, STATE.keys[key_id])
            else:
                self._send(404, {'error': 'no such key'})
            return
        if self.path.startswith('/api/v1/admin/policies'):
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            rest = self.path[len('/api/v1/admin/policies'):]
            if rest.strip('/'):
                pid = rest.strip('/')
                found = next((p for p in STATE.policies if p['id'] == pid), None)
                if found:
                    self._send(200, found)
                else:
                    self._send(404, {'error': 'no such policy'})
            else:
                self._send(200, STATE.policies)
            return
        if self.path.startswith('/api/v1/admin/guardrails'):
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            rest = self.path[len('/api/v1/admin/guardrails'):]
            if rest.strip('/'):
                gid = rest.strip('/')
                if gid in STATE.guardrails:
                    self._send(200, STATE.guardrails[gid])
                else:
                    self._send(404, {'error': 'no such guardrail'})
            else:
                self._send(200, list(STATE.guardrails.values()))
            return
        if self.path.startswith('/api/v1/admin/ai-providers'):
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            self._send(200, STATE.providers)
            return
        if self.path == '/api/v1/admin/detectors':
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            self._send(200, STATE.custom_detectors)
            return
        if self.path == '/api/v1/admin/built-in-detectors':
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            self._send(200, STATE.builtin_detectors)
            return
        if self.path == '/api/v1/model-groups':
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            self._send(200, STATE.model_groups)
            return
        if '/budget' in self.path:
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            self._send(200, {'spend': 1.5, 'budget': 10, 'budgetCycle': 'monthly'})
            return
        if self.path.startswith('/api/v1/admin/audit-logs'):
            if not self._sessioned():
                self._send(401, {'error': 'no session'})
                return
            if 'filter-options' in self.path:
                self._send(200, {'user': ['admin@example.com'],
                                 'workspace': ['Default'],
                                 'role': ['org_admin'],
                                 'action': ['Create', 'Delete', 'Update']})
                return
            params = dict(pair.split('=') for pair in
                          (self.path.split('?', 1) + [''])[1].split('&') if '=' in pair)
            offset = int(params.get('offset', '0'))
            limit = int(params.get('limit', '25'))
            items = STATE.audit_events[offset:offset + limit]
            self._send(200, {'items': items, 'total': len(STATE.audit_events),
                             'offset': offset,
                             'hasNext': offset + limit < len(STATE.audit_events),
                             'hasPrev': offset > 0, 'nextCursor': None})
            return
        if self.path == '/ai/openai/v1/models':
            auth = self.headers.get('Authorization', '')
            if auth == 'Bearer ' + GOOD_KEY:
                self._send(200, {'data': [{'id': 'm-1'}, {'id': 'm-2'}, {'id': 'm-3'}]})
            else:
                self._send(401, {'error': 'invalid key'})
            return
        self._send(404, {'error': 'not found'})

    def do_PUT(self):
        if not self._sessioned():
            self._send(401, {'error': 'no session'})
            return
        if not self.headers.get('X-CSRF-Token'):
            self._send(403, {'error': 'missing csrf'})
            return
        key_id = self._key_id_from('/api/v1/admin/virtual-keys/', '')
        if not key_id or key_id not in STATE.keys:
            self._send(404, {'error': 'no such key'})
            return
        STATE.last_put_body = self._body()
        STATE.keys[key_id].update(STATE.last_put_body)
        self._send(200, STATE.keys[key_id])

    def _key_id_from(self, prefix, suffix):
        if not self.path.startswith(prefix):
            return None
        rest = self.path[len(prefix):]
        if suffix:
            if not rest.endswith(suffix):
                return None
            rest = rest[:-len(suffix)]
        return rest or None


@pytest.fixture()
def fake():
    STATE.reset()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    STATE.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield STATE
    server.shutdown()
    server.server_close()


@pytest.fixture()
def config(fake):
    """Connector config dict pointed at the live fake gateway."""
    return {
        'server': 'http://127.0.0.1:{0}'.format(STATE.port),
        'username': STATE.username,
        'password': STATE.password,
        'verify_ssl': False,
        'data_plane_base': '',
        'timeout': '10',
    }


def make_client(config, **overrides):
    """Build a FaigClient from a connector-style config dict."""
    merged = dict(config)
    merged.update(overrides)
    return FaigClient(
        server=merged['server'],
        username=merged['username'],
        password=merged['password'],
        verify_ssl=merged.get('verify_ssl', False),
        data_plane_base=merged.get('data_plane_base') or None,
        timeout=merged.get('timeout') or 30,
    )
