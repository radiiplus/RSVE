"""Stable standard-library serialization for RSVE schema records."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from enum import Enum
from types import UnionType
from typing import Any, TypeVar, Union, get_args, get_origin, get_type_hints

SCHEMA_VERSION = "rsve.schema/1"
T = TypeVar("T")


def encode(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_record") and not isinstance(value, SchemaMixin):
        return {"__record__": value.to_record()}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if is_dataclass(value):
        return {field.name: encode(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): encode(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, frozenset):
        return [encode(item) for item in sorted(value, key=repr)]
    if isinstance(value, (tuple, list)):
        return [encode(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported schema value: {type(value).__name__}")


def _decode(annotation: Any, value: Any) -> Any:
    if isinstance(value, dict) and "__record__" in value and hasattr(annotation, "from_record"):
        return annotation.from_record(value["__record__"])
    origin = get_origin(annotation)
    args = get_args(annotation)
    if annotation is Any:
        if isinstance(value, dict) and "__bytes__" in value:
            return bytes.fromhex(value["__bytes__"])
        return value
    if origin is list:
        return [_decode(args[0], item) for item in value]
    if origin is tuple:
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], item) for item in value)
        return tuple(_decode(item_type, item) for item_type, item in zip(args, value))
    if origin is frozenset:
        return frozenset(_decode(args[0], item) for item in value)
    if origin is dict:
        return {key: _decode(args[1], item) for key, item in value.items()}
    if origin is None and isinstance(annotation, type) and issubclass(annotation, Enum):
        return annotation(value)
    if origin is None and isinstance(annotation, type) and is_dataclass(annotation):
        hints = get_type_hints(annotation)
        return annotation(**{
            field.name: _decode(hints.get(field.name, field.type), value[field.name])
            for field in fields(annotation)
        })
    # Optional/union annotations are supported conservatively for schema records.
    if origin in (Union, UnionType):
        for candidate in args:
            if candidate is type(None) and value is None:
                return None
            if candidate is not type(None):
                try:
                    return _decode(candidate, value)
                except (TypeError, ValueError):
                    pass
    return value


class SchemaMixin:
    """Mixin for records with an explicit schema version and stable type name."""

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": type(self).__name__,
            "payload": encode(self),
        }

    @classmethod
    def from_record(cls: type[T], record: dict[str, Any]) -> T:
        if record.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version: {record.get('schema_version')!r}")
        if record.get("type") != cls.__name__:
            raise ValueError(f"record type {record.get('type')!r} is not {cls.__name__!r}")
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("schema record payload must be an object")
        try:
            return _decode(cls, payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid {cls.__name__} schema payload") from exc
