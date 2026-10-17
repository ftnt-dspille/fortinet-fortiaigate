"""Add faig_workspace_id to every tagged Vault secret under a folder.

The onboarding playbook stamps faig_workspace_id now, but secrets created before
that change (or imported from elsewhere) do not have the tag yet - so the
'Revoke on Guardrail Block' playbook cannot find their peers. This fills them
in by reading faig_key_id from each secret, asking FortiAIGate for the key's
workspace, and patching the metadata. Secrets whose key is already gone are
skipped and reported.

    FAIG_URL=... FAIG_USERNAME=... FAIG_PASSWORD=... \
    VAULT_ADDR=... VAULT_TOKEN=... \
    python backfill_workspace_tag.py [--folder lab] [--dry-run]

Reads can run with any Vault token that has metadata read/list; the patch
needs the rotator policy's metadata patch, or a root token (what the demo uses).
"""
from __future__ import annotations
import argparse
import os
import sys
import time

import requests
import urllib3

from pyfortiaigate import FortiAIGate

urllib3.disable_warnings()


def walk(vault, tok, folder):
    """Every path under folder/, following nested LIST responses."""
    seen, pending = [], [folder.rstrip("/") + "/"]
    while pending:
        p = pending.pop(0)
        r = requests.get(f"{vault}/v1/secret/metadata/{p}?list=true",
                         headers={"X-Vault-Token": tok}, verify=False, timeout=10)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        for key in r.json().get("data", {}).get("keys", []):
            (pending if key.endswith("/") else seen).append(p + key)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", default="lab")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    vault = os.environ["VAULT_ADDR"].rstrip("/")
    tok = os.environ["VAULT_TOKEN"]
    g = FortiAIGate(os.environ["FAIG_URL"], os.environ["FAIG_USERNAME"], os.environ["FAIG_PASSWORD"], verify=False)
    hdr = {"X-Vault-Token": tok}
    tagged, filled, already, skipped, orphaned = 0, 0, 0, 0, []
    with g:
        for path in walk(vault, tok, args.folder):
            md = requests.get(f"{vault}/v1/secret/metadata/{path}", headers=hdr, verify=False, timeout=10).json()
            tags = md.get("data", {}).get("custom_metadata") or {}
            kid = tags.get("faig_key_id")
            if not kid:
                continue
            tagged += 1
            if tags.get("faig_workspace_id"):
                already += 1
                continue
            try:
                rec = g.virtual_key(kid) or {}
                ws = ((rec.get("workspace") or {}).get("id")
                      or rec.get("workspaceId") or "")
            except Exception as e:
                orphaned.append((path, kid, str(e)[:80]))
                skipped += 1
                continue
            if not ws:
                orphaned.append((path, kid, "no workspaceId on key"))
                skipped += 1
                continue
            print(f"{path}  key {kid[:8]}  workspace {ws[:8]}", "(dry run)" if args.dry_run else "")
            if not args.dry_run:
                requests.post(f"{vault}/v1/secret/metadata/{path}", headers=hdr, verify=False, timeout=10,
                              json={"custom_metadata": {**tags, "faig_workspace_id": ws}}).raise_for_status()
            filled += 1
            time.sleep(0.05)
    print(f"\n{tagged} tagged secrets, {already} already had faig_workspace_id, {filled} filled, {skipped} skipped")
    for row in orphaned:
        print(" skipped:", *row)
    sys.exit(0 if not orphaned else 2)


if __name__ == "__main__":
    main()
