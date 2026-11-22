#!/usr/bin/env python3
"""Run the attached Bor engine/runtime/environment region inventory."""

from __future__ import annotations

import argparse
import json

from rsve.bor_autonomous import attach_environment_observation, bor_autonomous_profile
from rsve.bor_callwithstate import bor_callwithstate_profile, bor_state_override_profile
from rsve.bor_environment import EnvironmentObservation
from rsve.bor_entrypoints import bor_entrypoint_regions
from rsve.bor_evidence import BorCallWithStateIngest, BorStorageRootIngest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", help="compiled bor-storage-root-probe.json path")
    parser.add_argument("--call-artifact", help="compiled bor-callwithstate-probe.json path")
    parser.add_argument("--environment-artifact", help="strict runtime/environment observation JSON")
    args = parser.parse_args()

    profile = bor_autonomous_profile()
    report = BorStorageRootIngest.load(args.artifact).attach_observation(profile.analyze())
    call_profile = bor_callwithstate_profile()
    call_report = call_profile.analyze()
    if args.call_artifact:
        call_report = BorCallWithStateIngest.load(args.call_artifact).attach_observation(call_report)
    override_profile = bor_state_override_profile()
    override_report = override_profile.analyze()
    route = bor_entrypoint_regions()
    route_report = route.analyze()
    if args.environment_artifact:
        environment = EnvironmentObservation.from_file(args.environment_artifact)
        report = attach_environment_observation(report, environment)
        route_report = attach_environment_observation(route_report, environment)
    print(json.dumps({
        "status": report.status.value,
        "reachability": report.reachability.value,
        "target": report.target_id,
        "build_hash": report.build_hash,
        "witness": [event.entry_point for event in report.witness.events],
        "regions": profile.attached_regions,
        "unknown_regions": profile.unknown_regions,
        "unresolved_uncertainty": report.unresolved_uncertainty,
        "entrypoint_route": {
            "status": route_report.status.value,
            "witness": [event.entry_point for event in route_report.witness.events] if route_report.witness else [],
            "unknown_regions": [item.unknown_id for item in route.unknown_regions],
            "unresolved_uncertainty": route_report.unresolved_uncertainty,
        },
        "evidence": [item.canonical() for item in report.evidence],
        "callwithstate": {
            "status": call_report.status.value,
            "witness": [event.entry_point for event in call_report.witness.events] if call_report.witness else [],
            "regions": call_profile.attached_regions,
            "unknown_regions": call_profile.unknown_regions,
            "unresolved_uncertainty": call_report.unresolved_uncertainty,
            "evidence": [item.canonical() for item in call_report.evidence],
        },
        "state_override": {
            "status": override_report.status.value,
            "witness": [event.entry_point for event in override_report.witness.events] if override_report.witness else [],
            "regions": override_profile.attached_regions,
            "unknown_regions": override_profile.unknown_regions,
            "unresolved_uncertainty": override_report.unresolved_uncertainty,
            "evidence": [item.canonical() for item in override_report.evidence],
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()
