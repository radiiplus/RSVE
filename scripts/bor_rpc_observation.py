#!/usr/bin/env python3
"""Collect before/after observations from a live Bor JSON-RPC endpoint."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import urllib.request
from typing import Any


def rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        envelope = json.load(response)
    if envelope.get("error") is not None:
        raise RuntimeError(f"{method}: {envelope['error']}")
    return envelope.get("result")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default="http://127.0.0.1:18545")
    parser.add_argument("--from", dest="sender", required=True)
    parser.add_argument("--to", dest="recipient", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    endpoint = args.rpc
    before = {
        "balance": rpc(endpoint, "eth_getBalance", [args.sender, "latest"]),
        "nonce": rpc(endpoint, "eth_getTransactionCount", [args.sender, "latest"]),
        "proof": rpc(endpoint, "eth_getProof", [args.sender, [], "latest"]),
    }
    call = rpc(endpoint, "eth_call", [{"from": args.sender, "to": args.recipient, "data": "0x"}, "latest"])
    override_call = rpc(endpoint, "eth_call", [
        {"from": args.sender, "to": args.recipient, "data": "0x"},
        "latest",
        {args.sender: {"balance": "0x1", "stateDiff": {"0x" + "00" * 32: "0x" + "00" * 31 + "01"}}},
    ])
    after = {
        "balance": rpc(endpoint, "eth_getBalance", [args.sender, "latest"]),
        "nonce": rpc(endpoint, "eth_getTransactionCount", [args.sender, "latest"]),
        "proof": rpc(endpoint, "eth_getProof", [args.sender, [], "latest"]),
    }
    result = {
        "classification": "RUNTIME_OBSERVATION",
        "observation": "rpc_call_and_state_override",
        "rpc": endpoint,
        "chain_id": rpc(endpoint, "eth_chainId", []),
        "block_number": rpc(endpoint, "eth_blockNumber", []),
        "sender": args.sender,
        "recipient": args.recipient,
        "before": before,
        "call_result": call,
        "state_override_call_result": override_call,
        "after": after,
        "canonical_state_unchanged": before == after,
        "nonce_unchanged": before["nonce"] == after["nonce"],
        "balance_unchanged": before["balance"] == after["balance"],
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
