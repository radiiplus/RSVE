#!/usr/bin/env python3
"""Run the focused Bor storage-root differential investigation."""

from __future__ import annotations

import argparse
import json

from rsve.bor_evidence import BorStorageRootIngest
from rsve.bor_profile import bor_storage_root_regression_profile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", help="compiled bor-storage-root-probe.json path")
    args = parser.parse_args()

    profile = bor_storage_root_regression_profile()
    report = profile.analyze()
    attached = BorStorageRootIngest.load(args.artifact).attach_observation(report)
    print(json.dumps({
        "status": attached.status.value,
        "reachability": attached.reachability.value,
        "objective": attached.objective,
        "target": attached.target_id,
        "build_hash": attached.build_hash,
        "witness": [event.entry_point for event in attached.witness.events],
        "final_state": attached.witness.final_state.as_dict(),
        "regions": profile.attached_regions,
        "unknown_regions": profile.unknown_regions,
        "source_refs": profile.source_refs,
        "unresolved_uncertainty": attached.unresolved_uncertainty,
        "evidence": [item.canonical() for item in attached.evidence],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
