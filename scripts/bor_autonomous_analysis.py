#!/usr/bin/env python3
"""Execute Bor and investigate the observations it actually emits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from rsve.bor_runtime_investigation import DEFAULT_BUILD, DEFAULT_COMMAND, imported_artifact, investigate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bor-workdir", default="/home/codespace/bor/bor-source")
    parser.add_argument("--bor-command", nargs="+", default=list(DEFAULT_COMMAND))
    parser.add_argument("--verify-command", nargs="+", help="optional independent verifier command")
    parser.add_argument("--revision", default=DEFAULT_BUILD)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--import-artifact", type=Path, help="attach an artifact as IMPORTED_ARTIFACT only")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = investigate(
        args.bor_command,
        cwd=args.bor_workdir,
        timeout_seconds=args.timeout,
        revision=args.revision,
        verify_argv=args.verify_command,
    )
    if args.import_artifact:
        result["imported_artifact"] = imported_artifact(args.import_artifact)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if result["classification"] == "UNRESOLVED":
        sys.exit(2)


if __name__ == "__main__":
    main()
