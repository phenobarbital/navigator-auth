from __future__ import annotations
from typing import Any, Optional
from dataclasses import is_dataclass, asdict

try:
    from .yaml_rs import dumps as _dumps, loads as _loads, dumps_formatted
    RUST_AVAILABLE = True
except ImportError:
    import yaml as _pyyaml
    RUST_AVAILABLE = False


def _prepare_object(obj: Any) -> Any:
    """Convert dataclasses and pydantic models to dictionaries before dumping."""
    try:
        from pydantic import BaseModel
        if isinstance(obj, BaseModel):
            return obj.model_dump()
    except ImportError:
        pass
    return asdict(obj) if is_dataclass(obj) else obj


def dumps(
    obj: Any,
    indent: int = 2,
    default_flow_style: bool = False,
    sort_keys: bool = False,
) -> str:
    """Serialize Python object to YAML string.

    Uses Rust serde_yaml when available (10-50x faster than PyYAML),
    falls back to PyYAML otherwise.
    """
    obj = _prepare_object(obj)
    if RUST_AVAILABLE:
        return dumps_formatted(
            obj,
            indent=indent,
            flow_style=default_flow_style,
            sort_keys=sort_keys,
        )
    return _pyyaml.dump(
        obj,
        indent=indent,
        default_flow_style=default_flow_style,
        sort_keys=sort_keys,
    )


def loads(yaml_str: str, loader: Optional[Any] = None) -> Any:
    """Deserialize YAML string to Python object.

    Uses Rust serde_yaml when available (5-20x faster than PyYAML),
    falls back to PyYAML otherwise.
    """
    if RUST_AVAILABLE:
        return _loads(yaml_str)
    if loader is not None:
        return _pyyaml.load(yaml_str, Loader=loader)
    return _pyyaml.safe_load(yaml_str)


__all__ = ["dumps", "loads", "RUST_AVAILABLE"]
