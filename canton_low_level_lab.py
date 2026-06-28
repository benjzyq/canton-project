#!/usr/bin/env python3
"""
Run the Canton DevNet low-level lab against the C8 validator APIs.

Secrets are read from environment variables:
  CANTON_CLIENT_ID
  CANTON_CLIENT_SECRET

The private key and live run state are stored in the state file, which defaults
to work/canton_lab_state.json relative to the current directory.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


AUTH_BASE = "https://auth.dev.digik.cantor8.tech"
VALIDATOR_BASE = "https://api.validator.dev.digik.cantor8.tech/api/validator"
LEDGER_BASE = "https://api.validator.dev.digik.cantor8.tech/api/ledger"
LEDGER_USER_ID = "validator-backend@clients"

TRANSFER_PREAPPROVAL_PROPOSAL = (
    "#splice-wallet:Splice.Wallet.TransferPreapproval:TransferPreapprovalProposal"
)
TRANSFER_PREAPPROVAL_TEMPLATE = "#splice-amulet:Splice.AmuletRules:TransferPreapproval"
HOLDING_INTERFACE = "#splice-api-token-holding-v1:Splice.Api.Token.HoldingV1:Holding"


class ApiError(RuntimeError):
    def __init__(self, method: str, url: str, status: int | None, body: str):
        super().__init__(f"{method} {url} failed: {status} {body[:500]}")
        self.method = method
        self.url = url
        self.status = status
        self.body = body


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def request_json(
    method: str,
    url: str,
    token: str | None = None,
    body: Any | None = None,
    timeout: int = 30,
) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise ApiError(method, url, exc.code, body_text) from exc
    except urllib.error.URLError as exc:
        raise ApiError(method, url, None, str(exc)) from exc


def obtain_token(client_id: str, client_secret: str) -> str:
    data = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
    ).encode("utf-8")
    url = f"{AUTH_BASE}/realms/master/protocol/openid-connect/token"
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))["access_token"]


def ensure_keypair(state: dict[str, Any]) -> None:
    if state.get("private_key_hex") and state.get("public_key_hex"):
        return

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    state["private_key_hex"] = private_bytes.hex()
    state["public_key_hex"] = public_bytes.hex()


def load_private_key(state: dict[str, Any]) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(state["private_key_hex"]))


def public_key_fingerprint(public_key_hex: str) -> str:
    public_key = bytes.fromhex(public_key_hex)
    digest = hashlib.sha256(bytes.fromhex("0000000C") + public_key).hexdigest()
    return f"1220{digest}"


def find_first_key(value: Any, key: str) -> Any | None:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = find_first_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_first_key(child, key)
            if found is not None:
                return found
    return None


def register_external_party(
    token: str,
    state: dict[str, Any],
    party_hint: str,
    state_path: Path,
) -> str:
    if state.get("topology_submitted") and state.get("party_id"):
        return state["party_id"]

    ensure_keypair(state)
    state["party_hint"] = party_hint
    public_key = state["public_key_hex"]

    generated = request_json(
        "POST",
        f"{VALIDATOR_BASE}/v0/admin/external-party/topology/generate",
        token,
        {"party_hint": party_hint, "public_key": public_key},
    )
    state["topology_generate_response"] = generated
    state["party_id"] = generated["party_id"]
    write_json(state_path, state)

    private_key = load_private_key(state)
    signed_topology_txs = []
    for tx in generated["topology_txs"]:
        digest = bytes.fromhex(tx["hash"])
        signed_topology_txs.append(
            {
                "topology_tx": tx["topology_tx"],
                "signed_hash": private_key.sign(digest).hex(),
            }
        )

    submitted = request_json(
        "POST",
        f"{VALIDATOR_BASE}/v0/admin/external-party/topology/submit",
        token,
        {"public_key": public_key, "signed_topology_txs": signed_topology_txs},
    )
    state["topology_submit_response"] = submitted
    state["topology_submitted"] = True
    state["party_id"] = submitted["party_id"]
    write_json(state_path, state)
    return state["party_id"]


def get_validator_and_dso_parties(token: str) -> tuple[str, str]:
    validator = request_json("GET", f"{VALIDATOR_BASE}/v0/validator-user", token)
    dso = request_json("GET", f"{VALIDATOR_BASE}/v0/scan-proxy/dso-party-id", token)
    return validator["party_id"], dso["dso_party_id"]


def get_active_synchronizer(token: str) -> str:
    rules = request_json("GET", f"{VALIDATOR_BASE}/v0/scan-proxy/amulet-rules", token)
    synchronizer = find_first_key(rules, "activeSynchronizer")
    if not isinstance(synchronizer, str) or not synchronizer:
        raise RuntimeError("Could not find activeSynchronizer in amulet rules response.")
    return synchronizer


def get_transfer_preapproval(token: str, party_id: str) -> dict[str, Any] | None:
    encoded_party = urllib.parse.quote(party_id, safe="")
    try:
        return request_json(
            "GET",
            f"{VALIDATOR_BASE}/v0/admin/transfer-preapprovals/by-party/{encoded_party}",
            token,
        )
    except ApiError as exc:
        if exc.status == 404:
            return None
        raise


def prepare_transfer_preapproval_proposal(
    token: str,
    party_id: str,
    validator_party: str,
    dso_party: str,
    synchronizer_id: str,
    command_suffix: str,
) -> dict[str, Any]:
    command_id = f"codex-preapproval-proposal-{command_suffix}"
    body = {
        "commands": [
            {
                "CreateCommand": {
                    "templateId": TRANSFER_PREAPPROVAL_PROPOSAL,
                    "createArguments": {
                        "receiver": party_id,
                        "provider": validator_party,
                        "expectedDso": dso_party,
                    },
                }
            }
        ],
        "userId": LEDGER_USER_ID,
        "commandId": command_id,
        "actAs": [party_id],
        "readAs": [party_id],
        "synchronizerId": synchronizer_id,
        "packageIdSelectionPreference": [],
        "verboseHashing": True,
    }
    return request_json(
        "POST",
        f"{LEDGER_BASE}/v2/interactive-submission/prepare",
        token,
        body,
    )


def sign_prepared_transaction_hash(
    state: dict[str, Any],
    prepared_transaction_hash: str,
) -> tuple[str, str]:
    try:
        digest = base64.b64decode(prepared_transaction_hash, validate=True)
    except ValueError:
        digest = bytes.fromhex(prepared_transaction_hash)
    signature = load_private_key(state).sign(digest)
    signed_by = public_key_fingerprint(state["public_key_hex"])
    return signed_by, base64.b64encode(signature).decode("ascii")


def sign_hex_hash(state: dict[str, Any], hash_hex: str) -> str:
    return load_private_key(state).sign(bytes.fromhex(hash_hex)).hex()


def execute_prepared_external_submission(
    token: str,
    state: dict[str, Any],
    party_id: str,
    prepared: dict[str, Any],
    signature_format: str,
) -> dict[str, Any]:
    signed_by, signature = sign_prepared_transaction_hash(
        state, prepared["preparedTransactionHash"]
    )
    body = {
        "preparedTransaction": prepared["preparedTransaction"],
        "partySignatures": {
            "signatures": [
                {
                    "party": party_id,
                    "signatures": [
                        {
                            "format": signature_format,
                            "signature": signature,
                            "signedBy": signed_by,
                            "signingAlgorithmSpec": "SIGNING_ALGORITHM_SPEC_ED25519",
                        }
                    ],
                }
            ]
        },
        "deduplicationPeriod": {"Empty": {}},
        "submissionId": f"codex-{uuid.uuid4()}",
        "userId": LEDGER_USER_ID,
        "hashingSchemeVersion": prepared["hashingSchemeVersion"],
    }
    return request_json(
        "POST",
        f"{LEDGER_BASE}/v2/interactive-submission/executeAndWait",
        token,
        body,
    )


def parse_contract_id_from_error(body: str) -> str | None:
    marker = "contract already exists:"
    if marker not in body:
        return None
    return body.split(marker, 1)[1].strip().strip('"} ')


def create_external_party_setup_proposal(
    token: str,
    party_id: str,
) -> str:
    result = request_json(
        "POST",
        f"{VALIDATOR_BASE}/v0/admin/external-party/setup-proposal",
        token,
        {"user_party_id": party_id},
        timeout=60,
    )
    return result["contract_id"]


def prepare_accept_external_party_setup_proposal(
    token: str,
    party_id: str,
    contract_id: str,
) -> dict[str, Any]:
    return request_json(
        "POST",
        f"{VALIDATOR_BASE}/v0/admin/external-party/setup-proposal/prepare-accept",
        token,
        {
            "contract_id": contract_id,
            "user_party_id": party_id,
            "verbose_hashing": True,
        },
        timeout=60,
    )


def submit_accept_external_party_setup_proposal(
    token: str,
    state: dict[str, Any],
    party_id: str,
    prepared: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "submission": {
            "party_id": party_id,
            "transaction": prepared["transaction"],
            "signed_tx_hash": sign_hex_hash(state, prepared["tx_hash"]),
            "public_key": state["public_key_hex"],
        }
    }
    return request_json(
        "POST",
        f"{VALIDATOR_BASE}/v0/admin/external-party/setup-proposal/submit-accept",
        token,
        body,
        timeout=60,
    )


def ensure_setup_preapproval(
    token: str,
    state: dict[str, Any],
    state_path: Path,
    party_id: str,
    wait_seconds: int,
) -> dict[str, Any] | None:
    existing = get_transfer_preapproval(token, party_id)
    if existing:
        state["transfer_preapproval"] = existing
        write_json(state_path, state)
        return existing

    if not state.get("setup_accept_response"):
        contract_id = state.get("setup_proposal_contract_id")
        if not contract_id:
            try:
                contract_id = create_external_party_setup_proposal(token, party_id)
            except ApiError as exc:
                if exc.status == 409:
                    existing_contract_id = parse_contract_id_from_error(exc.body)
                    if "TransferPreapproval contract already exists" in exc.body:
                        preapproval = get_transfer_preapproval(token, party_id)
                        state["transfer_preapproval"] = preapproval
                        write_json(state_path, state)
                        return preapproval
                    if existing_contract_id:
                        contract_id = existing_contract_id
                    else:
                        raise
                else:
                    raise
            state["setup_proposal_contract_id"] = contract_id
            write_json(state_path, state)

        prepared = prepare_accept_external_party_setup_proposal(token, party_id, contract_id)
        state["setup_accept_prepare_response"] = prepared
        write_json(state_path, state)

        submitted = submit_accept_external_party_setup_proposal(token, state, party_id, prepared)
        state["setup_accept_response"] = submitted
        state["transfer_preapproval_contract_id"] = submitted.get(
            "transfer_preapproval_contract_id"
        )
        write_json(state_path, state)

    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        existing = get_transfer_preapproval(token, party_id)
        if existing:
            state["transfer_preapproval"] = existing
            write_json(state_path, state)
            return existing
        time.sleep(5)

    if state.get("setup_accept_response"):
        return {
            "transfer_preapproval_contract_id": state["setup_accept_response"].get(
                "transfer_preapproval_contract_id"
            ),
            "update_id": state["setup_accept_response"].get("update_id"),
            "lookup_pending": True,
        }
    return None


def ensure_transfer_preapproval(
    token: str,
    state: dict[str, Any],
    state_path: Path,
    party_id: str,
    validator_party: str,
    dso_party: str,
    synchronizer_id: str,
    wait_seconds: int,
    signature_format: str,
    allow_setup_proposal_fallback: bool,
) -> dict[str, Any] | None:
    existing = get_transfer_preapproval(token, party_id)
    if existing:
        state["transfer_preapproval"] = existing
        write_json(state_path, state)
        return existing

    if not state.get("preapproval_execute_response"):
        suffix = state.get("party_hint", "party") + "-" + str(int(time.time()))
        prepared = prepare_transfer_preapproval_proposal(
            token, party_id, validator_party, dso_party, synchronizer_id, suffix
        )
        state["preapproval_prepare_response"] = prepared
        write_json(state_path, state)

        formats = [signature_format]
        fallback = "SIGNATURE_FORMAT_CONCAT"
        if signature_format != fallback:
            formats.append(fallback)

        errors: list[str] = []
        for current_format in formats:
            try:
                submitted = execute_prepared_external_submission(
                    token, state, party_id, prepared, current_format
                )
                state["preapproval_signature_format"] = current_format
                state["preapproval_execute_response"] = submitted
                write_json(state_path, state)
                break
            except ApiError as exc:
                errors.append(f"{current_format}: {exc.body[:500]}")
                if "signature" not in exc.body.lower() and "verify" not in exc.body.lower():
                    raise
        else:
            raise RuntimeError("Interactive submission failed: " + " | ".join(errors))

    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        existing = get_transfer_preapproval(token, party_id)
        if existing:
            state["transfer_preapproval"] = existing
            write_json(state_path, state)
            return existing
        time.sleep(5)

    if allow_setup_proposal_fallback:
        state["setup_preapproval_fallback_reason"] = (
            "Direct TransferPreapprovalProposal did not become visible before timeout."
        )
        write_json(state_path, state)
        return ensure_setup_preapproval(token, state, state_path, party_id, wait_seconds)
    return None


def ledger_end(token: str) -> int:
    result = request_json("GET", f"{LEDGER_BASE}/v2/state/ledger-end", token)
    return int(result["offset"])


def active_contracts(
    token: str,
    party_id: str,
    offset: int,
    identifier_filter: dict[str, Any],
) -> list[dict[str, Any]]:
    body = {
        "eventFormat": {
            "filtersByParty": {
                party_id: {
                    "cumulative": [
                        {"identifierFilter": identifier_filter}
                    ]
                }
            },
            "verbose": False,
        },
        "verbose": False,
        "activeAtOffset": offset,
    }
    result = request_json("POST", f"{LEDGER_BASE}/v2/state/active-contracts", token, body)
    contracts: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if "createdEvent" in value:
                contracts.append(value["createdEvent"])
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(result)
    return contracts


def active_holdings(token: str, party_id: str, offset: int) -> list[dict[str, Any]]:
    return active_contracts(
        token,
        party_id,
        offset,
        {
            "InterfaceFilter": {
                "value": {
                    "interfaceId": HOLDING_INTERFACE,
                    "includeInterfaceView": True,
                    "includeCreatedEventBlob": False,
                }
            }
        },
    )


def active_transfer_preapprovals(
    token: str, party_id: str, offset: int
) -> list[dict[str, Any]]:
    return active_contracts(
        token,
        party_id,
        offset,
        {
            "TemplateFilter": {
                "value": {
                    "templateId": TRANSFER_PREAPPROVAL_TEMPLATE,
                    "includeCreatedEventBlob": False,
                }
            }
        },
    )


@dataclass
class RunSummary:
    party_id: str
    validator_party: str
    dso_party: str
    synchronizer_id: str
    topology_submitted: bool
    preapproval_created: bool
    preapproval: dict[str, Any] | None
    ledger_offset: int
    preapproval_acs_count: int
    preapproval_acs: list[dict[str, Any]]
    holding_count: int
    holdings: list[dict[str, Any]]
    state_path: str


def run(args: argparse.Namespace) -> RunSummary:
    client_id = os.environ.get("CANTON_CLIENT_ID")
    client_secret = os.environ.get("CANTON_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit("Set CANTON_CLIENT_ID and CANTON_CLIENT_SECRET before running.")

    state_path = Path(args.state)
    state = read_json(state_path)
    party_hint = args.party_hint or state.get("party_hint") or f"qin-codex-{int(time.time())}"

    token = obtain_token(client_id, client_secret)
    party_id = register_external_party(token, state, party_hint, state_path)
    validator_party, dso_party = get_validator_and_dso_parties(token)
    synchronizer_id = get_active_synchronizer(token)
    state["validator_party"] = validator_party
    state["dso_party"] = dso_party
    state["synchronizer_id"] = synchronizer_id
    write_json(state_path, state)

    preapproval = ensure_transfer_preapproval(
        token,
        state,
        state_path,
        party_id,
        validator_party,
        dso_party,
        synchronizer_id,
        args.wait_preapproval_seconds,
        args.signature_format,
        args.allow_setup_proposal_fallback,
    )
    offset = ledger_end(token)
    preapproval_acs = active_transfer_preapprovals(token, party_id, offset)
    holdings = active_holdings(token, party_id, offset)

    return RunSummary(
        party_id=party_id,
        validator_party=validator_party,
        dso_party=dso_party,
        synchronizer_id=synchronizer_id,
        topology_submitted=bool(state.get("topology_submitted")),
        preapproval_created=preapproval is not None,
        preapproval=preapproval,
        ledger_offset=offset,
        preapproval_acs_count=len(preapproval_acs),
        preapproval_acs=preapproval_acs,
        holding_count=len(holdings),
        holdings=holdings,
        state_path=str(state_path),
    )


def write_report(summary: RunSummary, path: Path) -> None:
    preapproval_contract_id = (
        find_first_key(summary.preapproval, "contractId")
        or find_first_key(summary.preapproval, "contract_id")
        or find_first_key(summary.preapproval, "transfer_preapproval_contract_id")
    )
    preapproval_update_id = (
        find_first_key(summary.preapproval, "updateId")
        or find_first_key(summary.preapproval, "update_id")
    )
    holding_contract_ids = [
        str(find_first_key(holding, "contractId"))
        for holding in summary.holdings
        if find_first_key(holding, "contractId")
    ]
    lines = [
        "# Canton DevNet Low-Level Lab Report",
        "",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        "No OAuth secret or private key material is included in this report.",
        "",
        "## Parties",
        "",
        f"- External party: `{summary.party_id}`",
        f"- Validator party: `{summary.validator_party}`",
        f"- DSO party: `{summary.dso_party}`",
        f"- Active synchronizer: `{summary.synchronizer_id}`",
        "",
        "## Lab Steps",
        "",
        f"- External party topology submitted: `{'yes' if summary.topology_submitted else 'no'}`",
        f"- Transfer preapproval visible: `{'yes' if summary.preapproval_created else 'no'}`",
        f"- Transfer preapproval contracts visible via ACS: `{summary.preapproval_acs_count}`",
        f"- Ledger ACS query offset: `{summary.ledger_offset}`",
        f"- Holding contracts visible for the external party: `{summary.holding_count}`",
    ]
    if preapproval_contract_id:
        lines.append(f"- Transfer preapproval contract id: `{preapproval_contract_id}`")
    if preapproval_update_id:
        lines.append(f"- Transfer preapproval update id: `{preapproval_update_id}`")
    if holding_contract_ids:
        lines.append("")
        lines.append("## Holding Contract IDs")
        lines.append("")
        for contract_id in holding_contract_ids:
            lines.append(f"- `{contract_id}`")
    lines.extend(
        [
            "",
            "## Remaining External Action",
            "",
            "Canton Coins are not minted by this script. Ask the DevNet team to send CC to the external party above, then rerun the script to refresh the Holding ACS query.",
            "",
            "Optional Token Standard transfer was not executed because no funded balance and no recipient party were provided.",
            "",
            "## Rerun",
            "",
            "```powershell",
            "$env:CANTON_CLIENT_ID='hackathon'",
            "$env:CANTON_CLIENT_SECRET='<from the lab document>'",
            "python outputs\\canton_low_level_lab.py --report outputs\\canton_lab_report.md",
            "```",
            "",
            "The default path uses external-party topology plus Ledger interactive submission. The validator setup-proposal helper is only used when rerun with `--allow-setup-proposal-fallback`.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--party-hint", help="Party hint for a new external party.")
    parser.add_argument("--state", default="work/canton_lab_state.json")
    parser.add_argument("--wait-preapproval-seconds", type=int, default=90)
    parser.add_argument(
        "--signature-format",
        default="SIGNATURE_FORMAT_RAW",
        choices=["SIGNATURE_FORMAT_RAW", "SIGNATURE_FORMAT_CONCAT"],
    )
    parser.add_argument(
        "--allow-setup-proposal-fallback",
        action="store_true",
        help="Use /v0/admin/external-party/setup-proposal only as an explicit fallback.",
    )
    parser.add_argument("--report", help="Write a sanitized Markdown report.")
    args = parser.parse_args()

    summary = run(args)
    if args.report:
        write_report(summary, Path(args.report))
    print(json.dumps(summary.__dict__, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
