#!/usr/bin/env python3
"""Deploy the FAIG + Vault KV connectors to the FortiSOAR lab appliance.

pyfsr throughout: uploads the packaged connector tarballs (with $replace so
redeploys are idempotent), waits for the install to activate, creates named
connector configurations, marks them default, and healthchecks each
configuration through the connector's own read-only operation.

Reads everything from tests/.env (FSR_*, FAIG_*, VAULT_INTERNAL_ADDR,
VAULT_TOKEN). Usage:
    python3 scripts/deploy_lab.py            # install + configure + verify
    python3 scripts/deploy_lab.py --verify   # only re-run the verifications
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_env(path: Path) -> dict:
    values = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        values[key.strip()] = value
    return values


def fsr_client(env: dict):
    from pyfsr import FortiSOAR
    return FortiSOAR(
        env['FSR_BASE_URL'],
        username=env.get('FSR_USERNAME', 'csadmin'),
        password=env['FSR_PASSWORD'],
        verify_ssl=(env.get('FSR_VERIFY_SSL', 'false').lower() == 'true'),
    )


def info_version(repo: Path) -> str:
    return json.load(open(repo / 'info.json'))['version']


def install(client, repo: Path, name: str, timeout: float = 180.0) -> None:
    version = info_version(repo)
    tgz = repo / 'dist' / '{0}-{1}.tgz'.format(name, version)
    if not tgz.exists():
        sys.exit('missing {0} - run scripts/package.sh inside {1}'.format(tgz, name))
    client.connectors.install_from_file(str(tgz), replace=True, wait=True)
    wait_for_active(client, name, timeout)
    print('installed {0} v{1}'.format(name, version))


def wait_for_active(client, name: str, timeout: float) -> None:
    """list_configured() until the connector shows up and is active -
    the import job finishing does not mean the record is live yet."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for entry in client.connectors.list_configured(refresh=True):
            if entry.name == name and entry.active is not False:
                return
        time.sleep(3)
    sys.exit('{0} did not activate within {1}s (check the import job)'.format(
        name, int(timeout)))


def configure(client, connector_name, config_name, config) -> None:
    client.connectors.create_configuration(
        connector=connector_name,
        config=config,
        name=config_name,
        version=info_version(REPO if connector_name.startswith('fortinet') else REPO.parent / 'hashicorp-vault-kv'),
        default=True,
        exist_ok=True,
    )
    # Registering the default is its own operation: the appliance ignores the
    # default flag on create, and playbook steps that reference config '' only
    # resolve when the connector has a registered default (else INTEGRATION-12).
    client.connectors.set_default_configuration(connector_name, name=config_name)
    print('configuration {0}: default, ready'.format(config_name))


def verify(client, connector_name, operation, config_name, params) -> None:
    result = client.connectors.execute(
        connector=connector_name, operation=operation, config=config_name,
        params=params)
    data = getattr(result, 'data', result)
    print('  {0}.{1} -> {2}'.format(
        connector_name, operation, str(data)[:160]))
    if getattr(result, 'ok', True) is not True:
        sys.exit('verification failed for {0}.{1}: {2}'.format(
            connector_name, operation, getattr(result, 'message', '')))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify', action='store_true',
                        help='skip install/config, only re-run verifications')
    args = parser.parse_args()

    env = load_env(REPO / 'tests' / '.env')
    missing = [k for k in ('FSR_BASE_URL', 'FSR_PASSWORD', 'FAIG_MGMT_URL',
                           'FAIG_ADMIN_USER', 'FAIG_ADMIN_PASS',
                           'VAULT_INTERNAL_ADDR', 'VAULT_TOKEN')
               if not env.get(k)]
    if missing:
        sys.exit('tests/.env is missing: {0}'.format(', '.join(missing)))

    vault_repo = REPO.parent / 'hashicorp-vault-kv'

    client = fsr_client(env)
    print('connected: {0}'.format(env['FSR_BASE_URL'].split('//')[-1]))

    if not args.verify:
        install(client, REPO, 'fortinet-fortiaigate')
        install(client, vault_repo, 'hashicorp-vault-kv')

        configure(client, 'fortinet-fortiaigate', 'faig-lab', {
            'server': env['FAIG_MGMT_URL'],
            'username': env['FAIG_ADMIN_USER'],
            'password': env['FAIG_ADMIN_PASS'],
            'verify_ssl': False,
            'data_plane_base': '',
            'timeout': '30',
        })
        configure(client, 'hashicorp-vault-kv', 'vault-lab', {
            'server': env['VAULT_INTERNAL_ADDR'],
            'token': env['VAULT_TOKEN'],
            'mount': 'secret',
            'verify_ssl': False,
            'timeout': '30',
        })

    print('healthchecks:')
    verify(client, 'fortinet-fortiaigate', 'list_workspaces', 'faig-lab', {})
    verify(client, 'hashicorp-vault-kv', 'get_health', 'vault-lab', {})
    verify(client, 'hashicorp-vault-kv', 'read_secret', 'vault-lab',
           {'path': 'lab/ai'})
    print('all good.')


if __name__ == '__main__':
    main()
