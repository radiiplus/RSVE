"""Dependency-free OpenTelemetry-compatible boundary for RSVE events."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from .model import ExecutionMode, Fidelity, State, TraceEvent


class OpenTelemetryAdapter:
    """Map canonical RSVE events to/from an OTLP-shaped JSON object.

    This is a wire-shape adapter, not an OpenTelemetry SDK integration. The
    core therefore remains usable when no OTel package is installed.
    """

    schema_version = "rsve.otel/1"

    def export(self, events: Sequence[TraceEvent], *, target: Mapping[str, str] | None = None) -> dict[str, Any]:
        target = dict(target or {})
        spans = []
        for event in events:
            attributes = {
                "rsve.event_id": event.event_id,
                "rsve.trace_id": event.trace_id,
                "rsve.run_id": event.run_id,
                "rsve.parent_event_id": event.parent_event_id or "",
                "rsve.entry_point": event.entry_point,
                "rsve.component": event.component,
                "rsve.mode": event.mode.value,
                "rsve.fidelity": event.fidelity.value,
                "rsve.input_representation": event.input_representation,
                "rsve.output_representation": event.output_representation,
                "rsve.state_before_id": event.state_before_id,
                "rsve.state_after_id": event.state_after_id,
                "rsve.guard_result": event.guard_result,
                "rsve.request": json.dumps(event.request, sort_keys=True, default=str),
                "rsve.before": json.dumps(event.before.canonical(), sort_keys=True, default=str),
                "rsve.after": json.dumps(event.after.canonical(), sort_keys=True, default=str),
                "rsve.observation": json.dumps(event.observation, sort_keys=True, default=str),
                "rsve.evidence_source": event.evidence_source,
                "rsve.evidence_refs": json.dumps(event.evidence_refs),
                "rsve.correlation_uncertain": event.correlation_uncertain,
            }
            spans.append({
                "traceId": _trace_id(event.trace_id),
                "spanId": _span_id(event.event_id),
                "parentSpanId": _span_id(event.parent_event_id) if event.parent_event_id else "",
                "name": event.operation,
                "startTimeUnixNano": event.timestamp_ns,
                "endTimeUnixNano": event.timestamp_ns,
                "attributes": attributes,
                "events": [{
                    "name": "rsve.observation",
                    "timeUnixNano": event.timestamp_ns,
                    "attributes": {"value": attributes["rsve.observation"]},
                }],
            })
        return {
            "rsve_schema_version": self.schema_version,
            "resource": {"attributes": target},
            "resourceSpans": [{"scopeSpans": [{"scope": {"name": "rsve"}, "spans": spans}]}],
        }

    def import_events(self, payload: Mapping[str, Any]) -> tuple[TraceEvent, ...]:
        if payload.get("rsve_schema_version") != self.schema_version:
            raise ValueError("unsupported RSVE OTel schema version")
        spans = []
        for resource_span in payload.get("resourceSpans", ()):
            for scope_span in resource_span.get("scopeSpans", ()):
                spans.extend(scope_span.get("spans", ()))
        events: list[TraceEvent] = []
        for order, span in enumerate(spans):
            attrs = span.get("attributes", {})
            events.append(TraceEvent(
                operation=span.get("name", "unknown"),
                entry_point=attrs.get("rsve.entry_point", "unknown"),
                request=json.loads(attrs.get("rsve.request", "{}")),
                before=State(json.loads(attrs.get("rsve.before", "{}"))),
                after=State(json.loads(attrs.get("rsve.after", "{}"))),
                observation=json.loads(attrs.get("rsve.observation", "{}")),
                fidelity=Fidelity(attrs.get("rsve.fidelity", Fidelity.OBSERVED.value)),
                mode=ExecutionMode(attrs.get("rsve.mode", ExecutionMode.INSTRUMENTED.value)),
                event_id=attrs.get("rsve.event_id", ""),
                run_id=attrs.get("rsve.run_id", ""),
                trace_id=attrs.get("rsve.trace_id", _original_trace_id(span.get("traceId", ""))),
                parent_event_id=attrs.get("rsve.parent_event_id") or None,
                component=attrs.get("rsve.component", ""),
                input_representation=attrs.get("rsve.input_representation", ""),
                output_representation=attrs.get("rsve.output_representation", ""),
                state_before_id=attrs.get("rsve.state_before_id", ""),
                state_after_id=attrs.get("rsve.state_after_id", ""),
                guard_result=attrs.get("rsve.guard_result"),
                evidence_source=attrs.get("rsve.evidence_source", ""),
                evidence_refs=tuple(json.loads(attrs.get("rsve.evidence_refs", "[]"))),
                timestamp_ns=span.get("startTimeUnixNano"),
                ordering=order,
                correlation_uncertain=bool(attrs.get("rsve.correlation_uncertain", False)),
            ))
        return tuple(events)


def _trace_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _span_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _original_trace_id(value: str) -> str:
    return value
