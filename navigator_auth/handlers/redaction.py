"""Allowlist-driven redaction for the auth model CRUD surfaces (FEAT-105).

Pure, synchronous projection primitives shared by ``UserIdentityHandler``,
``UserAccountHandler`` and ``PartnerKeyHandler``. They sit on two different
handler base classes, so nothing here may touch ``self``, a request, or a
database connection.

The contract is one-directional: a column is serialized only when it is
named in ``public_columns``. Nothing in this module can ever *add* a column
to a response, which is what makes "a credential cannot be reached through
any parameter combination" (spec G3) a property of construction rather than
of review.
"""
from typing import Any, Optional, Union

from datamodel import BaseModel


def _row_value(row: Any, column: str, default: Any = None) -> Any:
    """Read one column from a row, whichever shape it has.

    Args:
        row: A ``dict``, a ``datamodel`` model instance, or any object.
        column: Column name to read.
        default: Returned when the column is absent.

    Returns:
        The column value, or ``default``.
    """
    if isinstance(row, dict):
        return row.get(column, default)
    return getattr(row, column, default)


def safe_fields(
    fields: Optional[list[str]],
    public_columns: frozenset[str],
) -> Optional[list[str]]:
    """Intersect a caller projection with the allowlist (never a union).

    Args:
        fields: The columns the caller asked for (``?fields=``), or ``None``
            when no projection was requested.
        public_columns: The handler's allowlist.

    Returns:
        ``None`` when ``fields`` is ``None`` — meaning "no projection was
        asked for", which callers must read as "serialize the whole
        allowlist". Otherwise the members of ``fields`` that are in
        ``public_columns``, in the caller's order, which may be an empty
        list when the caller asked **only** for forbidden columns.
    """
    if fields is None:
        return None
    result: list[str] = []
    for name in fields:
        if name in public_columns and name not in result:
            result.append(name)
    return result


def redact_row(
    row: Union[BaseModel, dict, None],
    public_columns: frozenset[str],
    fields: Optional[list[str]] = None,
) -> dict:
    """Project one row onto ``public_columns`` (intersected with ``fields``).

    Args:
        row: The row to project, in any of the three accepted shapes.
        public_columns: The handler's allowlist.
        fields: Optional caller projection, already safe to pass raw — it is
            run through :func:`safe_fields` here.

    Returns:
        A plain ``dict`` holding only allowed columns. ``{}`` when ``row`` is
        ``None`` or nothing is allowed.
    """
    if row is None:
        return {}
    columns = safe_fields(fields, public_columns)
    if columns is None:
        columns = sorted(public_columns)
    return {name: _row_value(row, name) for name in columns}


def redact_rows(
    rows: Any,
    public_columns: frozenset[str],
    fields: Optional[list[str]] = None,
) -> Any:
    """Vectorized :func:`redact_row`, preserving list-vs-scalar shape.

    Args:
        rows: A single row, a list of rows, or ``None``.
        public_columns: The handler's allowlist.
        fields: Optional caller projection.

    Returns:
        A ``list[dict]`` for a list input, a ``dict`` for a scalar input, and
        ``None`` for ``None`` — the shape the caller passed in.
    """
    if rows is None:
        return None
    if isinstance(rows, (list, tuple)):
        return [redact_row(r, public_columns, fields) for r in rows]
    return redact_row(rows, public_columns, fields)


def redact_schema(
    schema: dict,
    credential_columns: frozenset[str],
) -> dict:
    """Strip credential columns from a ``Model.schema(as_dict=True)`` payload.

    Used by the ``:meta`` path so the JSON-schema response cannot enumerate
    the columns the rest of this module refuses to serialize.

    Args:
        schema: The payload returned by ``Model.schema(as_dict=True)``.
        credential_columns: Columns to remove from ``properties`` and
            ``required``.

    Returns:
        A **new** dict. The argument is never mutated (the model's schema is
        memoized and shared process-wide).
    """
    result = dict(schema)
    props = schema.get("properties")
    if isinstance(props, dict):
        result["properties"] = {
            k: v for k, v in props.items() if k not in credential_columns
        }
    required = schema.get("required")
    if isinstance(required, (list, tuple)):
        result["required"] = [c for c in required if c not in credential_columns]
    return result
