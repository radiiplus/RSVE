#!/usr/bin/env python3
"""Observe one isolated Bor RPC interaction across process and host boundaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any
import urllib.request


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def _text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _filesystem_snapshot(root: Path) -> dict[str, Any]:
    """Capture bounded hashes for the isolated node's persistence boundary."""
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        files.append({
            "path": str(path.relative_to(root)),
            "size": size,
            "sha256": _sha256(path),
        })
        total_bytes += size
        if len(files) >= 512:
            break
    return {"file_count": len(files), "total_bytes": total_bytes, "files": files}


def _filesystem_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_files = {item["path"]: item for item in before.get("files", [])}
    after_files = {item["path"]: item for item in after.get("files", [])}
    return {
        "created": sorted(set(after_files) - set(before_files)),
        "removed": sorted(set(before_files) - set(after_files)),
        "changed": sorted(
            path for path in set(before_files) & set(after_files)
            if before_files[path] != after_files[path]
        ),
        "snapshot_truncated": before.get("file_count") == 512 or after.get("file_count") == 512,
    }


def _host_snapshot() -> dict[str, Any]:
    meminfo = _text(Path("/proc/meminfo")) or ""
    memory = {}
    for line in meminfo.splitlines():
        key, _, value = line.partition(":")
        if key in {"MemTotal", "MemAvailable", "SwapTotal", "HugePages_Total"}:
            memory[key] = value.strip()
    cpuinfo = _text(Path("/proc/cpuinfo")) or ""
    model = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("model name")), None)
    cgroup = {}
    for name in ("cpu.max", "memory.max", "pids.max"):
        value = _text(Path("/sys/fs/cgroup") / name)
        if value is not None:
            cgroup[name] = value.strip()
    return {
        "uname": dict(zip(("system", "node", "release", "version", "machine"), platform.uname())),
        "kernel_version_sha256": hashlib.sha256((_text(Path("/proc/version")) or "").encode()).hexdigest(),
        "cpu_count": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "cpu_model": model,
        "cpuinfo_sha256": hashlib.sha256(cpuinfo.encode()).hexdigest(),
        "memory": memory,
        "cgroup_limits": cgroup,
        "kernel_controls": {
            name: _text(Path("/proc/sys/kernel") / name)
            for name in ("yama/ptrace_scope", "perf_event_paranoid")
            if _text(Path("/proc/sys/kernel") / name) is not None
        },
    }


def _syscall_trace(trace_root: Path) -> dict[str, Any]:
    files = sorted(trace_root.glob("syscall-trace*"))
    counts: dict[str, int] = {}
    line_count = 0
    digest = hashlib.sha256()
    for path in files:
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        digest.update(raw)
        for line in raw.decode("utf-8", errors="replace").splitlines():
            line_count += 1
            match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\(", line)
            if match:
                name = match.group(1)
                counts[name] = counts.get(name, 0) + 1
    return {
        "available": bool(files),
        "file_count": len(files),
        "line_count": line_count,
        "sha256": digest.hexdigest() if files else None,
        "syscall_counts": dict(sorted(counts.items())),
    }


def rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        envelope = json.load(response)
    if envelope.get("error") is not None:
        raise RuntimeError(f"{method}: {envelope['error']}")
    return envelope.get("result")


def process_snapshot(pid: int) -> dict[str, Any]:
    root = Path("/proc") / str(pid)
    executable = root / "exe"
    maps = root / "maps"
    cmdline = _text(root / "cmdline")
    environment = _text(root / "environ")
    status = _text(root / "status") or ""
    status_fields = {}
    for line in status.splitlines():
        if line.startswith((
            "Name:", "State:", "Threads:", "VmRSS:", "VmPeak:",
            "CapEff:", "CapBnd:", "NoNewPrivs:", "Seccomp:",
            "Seccomp_filters:", "Cpus_allowed_list:",
            "voluntary_ctxt_switches:", "nonvoluntary_ctxt_switches:",
        )):
            key, _, value = line.partition(":")
            status_fields[key] = value.strip()
    try:
        fd_count = len(list((root / "fd").iterdir()))
    except OSError:
        fd_count = None
    return {
        "pid": pid,
        "executable": os.readlink(executable) if executable.exists() else None,
        "executable_sha256": _sha256(executable),
        "argv_sha256": hashlib.sha256((cmdline or "").replace("\x00", "\n").encode()).hexdigest(),
        "environment_sha256": hashlib.sha256((environment or "").encode()).hexdigest(),
        "maps_sha256": hashlib.sha256((maps.read_bytes() if maps.exists() else b"")).hexdigest(),
        "status": status_fields,
        "scheduler": {
            "sched_sha256": hashlib.sha256((_text(root / "sched") or "").encode()).hexdigest(),
            "schedstat": (_text(root / "schedstat") or "").strip(),
        },
        "fd_count": fd_count,
        "fd_target_sha256": hashlib.sha256(
            "\n".join(sorted(
                target for target in (
                    os.readlink(path) for path in (root / "fd").iterdir()
                    if path.exists()
                )
            )).encode()
        ).hexdigest() if (root / "fd").exists() else None,
        "io": _text(root / "io"),
        "cgroup": _text(root / "cgroup"),
        "namespaces": {
            name: os.stat(root / "ns" / name).st_ino
            for name in ("mnt", "pid", "net", "user", "uts")
            if (root / "ns" / name).exists()
        },
    }


def wait_for_rpc(url: str, process: subprocess.Popen[bytes], deadline: float) -> None:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Bor exited before RPC became available: {process.returncode}")
        try:
            rpc(url, "eth_chainId", [])
            return
        except Exception:
            time.sleep(0.1)
    raise TimeoutError("Bor RPC did not become available")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="/tmp/bor-bin")
    parser.add_argument("--port", type=int, default=18546)
    parser.add_argument("--dev-period", type=int, default=3600)
    parser.add_argument("--sender")
    parser.add_argument("--recipient", default="0x3333333333333333333333333333333333333333")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    rpc_url = f"http://127.0.0.1:{args.port}"
    with tempfile.TemporaryDirectory(prefix="rsve-bor-cross-layer-") as data_dir, tempfile.TemporaryDirectory(prefix="rsve-bor-cross-layer-trace-") as trace_dir:
        target_command = [
            args.binary, "server", "--dev", "--dev.period", str(args.dev_period),
            "--datadir", data_dir, "--http", "--http.addr", "127.0.0.1",
            "--http.port", str(args.port), "--http.api", "eth,net,web3,debug,txpool",
            "--http.vhosts", "localhost", "--http.corsdomain", "localhost",
            "--nodiscover", "--maxpeers", "0", "--bor.withoutheimdall",
            "--bor.devfakeauthor", "--disable-tx-propagation",
        ]
        trace_binary = shutil.which("strace")
        command = (
            [trace_binary, "-ff", "-qq", "-tt", "-e", "trace=%file,%network,%process,%desc",
             "-o", str(Path(trace_dir) / "syscall-trace"), *target_command]
            if trace_binary else target_command
        )
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for_rpc(rpc_url, process, time.monotonic() + 30)
            before_host = _host_snapshot()
            before_process = process_snapshot(process.pid)
            before_filesystem = _filesystem_snapshot(Path(data_dir))
            accounts = rpc(rpc_url, "eth_accounts", [])
            sender = args.sender or (accounts[0] if accounts else None)
            before_chain = {
                "chain_id": rpc(rpc_url, "eth_chainId", []),
                "block_number": rpc(rpc_url, "eth_blockNumber", []),
            }
            before_account = None
            if sender:
                before_account = {
                    "address": sender,
                    "balance": rpc(rpc_url, "eth_getBalance", [sender, "latest"]),
                    "nonce": rpc(rpc_url, "eth_getTransactionCount", [sender, "latest"]),
                    "proof": rpc(rpc_url, "eth_getProof", [sender, [], "latest"]),
                }
                before_chain["account_discovered"] = args.sender is None
            control_before_filesystem = _filesystem_snapshot(Path(data_dir))
            control_result = rpc(rpc_url, "eth_chainId", [])
            control_after_filesystem = _filesystem_snapshot(Path(data_dir))
            interaction_before_filesystem = _filesystem_snapshot(Path(data_dir))
            if sender:
                call = rpc(rpc_url, "eth_call", [{"from": sender, "to": args.recipient, "data": "0x"}, "latest"])
            else:
                call = control_result
            interaction_after_filesystem = _filesystem_snapshot(Path(data_dir))
            time.sleep(0.2)
            after_chain = {
                "chain_id": rpc(rpc_url, "eth_chainId", []),
                "block_number": rpc(rpc_url, "eth_blockNumber", []),
            }
            after_account = None
            if sender:
                after_account = {
                    "address": sender,
                    "balance": rpc(rpc_url, "eth_getBalance", [sender, "latest"]),
                    "nonce": rpc(rpc_url, "eth_getTransactionCount", [sender, "latest"]),
                    "proof": rpc(rpc_url, "eth_getProof", [sender, [], "latest"]),
                }
            after_process = process_snapshot(process.pid)
            after_filesystem = _filesystem_snapshot(Path(data_dir))
            after_host = _host_snapshot()
            result = {
                "classification": "RUNTIME_OBSERVATION",
                "observation": "bor-rpc-cross-layer-boundary",
                "command": command,
                "target_command": target_command,
                "rpc": rpc_url,
                "host_before": before_host,
                "before": {"process": before_process, "chain": before_chain},
                "interaction": {"method": "eth_call" if sender else "eth_chainId", "sender": sender, "result": call},
                "account_before": before_account,
                "account_after": after_account,
                "after": {"process": after_process, "chain": after_chain},
                "host_after": after_host,
                "canonical_account_unchanged": before_account == after_account if sender else None,
                "filesystem": {
                    "before": before_filesystem,
                    "after": after_filesystem,
                    "delta": _filesystem_delta(before_filesystem, after_filesystem),
                    "interaction_window": {
                        "before": interaction_before_filesystem,
                        "after": interaction_after_filesystem,
                        "delta": _filesystem_delta(interaction_before_filesystem, interaction_after_filesystem),
                    },
                    "control_window": {
                        "method": "eth_chainId",
                        "result": control_result,
                        "delta": _filesystem_delta(control_before_filesystem, control_after_filesystem),
                    },
                },
                "process_identity_unchanged": (
                    before_process["pid"] == after_process["pid"]
                    and before_process["executable_sha256"] == after_process["executable_sha256"]
                    and before_process["argv_sha256"] == after_process["argv_sha256"]
                ),
                "unknown_regions": [
                    {
                        "region_id": "host.kernel",
                        "layer": "kernel",
                        "status": "unresolved",
                        "observed": True,
                        "measured": ["uname", "kernel_version_hash", "cgroup_limits", "namespace_ids", "seccomp", "capabilities"],
                        "unmeasured": ["kernel-internal effects outside the traced process"],
                    },
                    {
                        "region_id": "host.hardware",
                        "layer": "environment",
                        "status": "unresolved",
                        "observed": True,
                        "measured": ["cpu_affinity", "cpu_model", "memory_limits", "cpuinfo_hash"],
                        "unmeasured": ["hypervisor behavior and hardware faults"],
                    },
                    {
                        "region_id": "runtime.scheduler",
                        "layer": "process",
                        "status": "unresolved",
                        "observed": True,
                        "measured": ["thread_count", "scheduler_snapshot", "context_switches", "syscall_trace"],
                        "unmeasured": ["Go scheduler decisions between snapshots"],
                    },
                ],
            }
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        result["syscall_trace"] = _syscall_trace(Path(trace_dir))

    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
