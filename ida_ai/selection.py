"""Address, byte-pattern, and SQLite selection helpers shared by the CLI."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Iterable

from .db import ida_ea


def parse_int(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    if not text:
        raise ValueError("address/value cannot be empty")
    if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", text):
        return int(text, 16)
    return int(text, 10)


def parse_hex_bytes(text: str) -> bytes:
    """Parse ``90 90``, ``0x9090``, or a compact hex string."""

    cleaned = re.sub(r"0x", "", text.strip(), flags=re.IGNORECASE)
    cleaned = re.sub(r"[\s,:_-]+", "", cleaned)
    if not cleaned:
        raise ValueError("byte string cannot be empty")
    if len(cleaned) % 2:
        raise ValueError(f"hex byte string has odd length: {text!r}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex bytes: {text!r}") from exc


@dataclass(frozen=True)
class BytePattern:
    values: tuple[int, ...]
    mask: tuple[int, ...]

    @property
    def length(self) -> int:
        return len(self.values)

    def matches(self, data: bytes, offset: int = 0) -> bool:
        if offset < 0 or offset + self.length > len(data):
            return False
        return all(
            (data[offset + index] & mask) == (value & mask)
            for index, (value, mask) in enumerate(zip(self.values, self.mask))
        )


def parse_pattern(pattern: str, mask: str | None = None) -> BytePattern:
    """Parse hex bytes with ``??`` wildcards or a separate hex mask.

    Examples: ``48 8B ?? ??``, or ``--pattern '48 8B 00 00' --mask 'FF FF 00 00'``.
    """

    tokens = pattern.replace(",", " ").split()
    if len(tokens) == 1 and " " not in pattern.strip() and "-" not in pattern:
        compact = tokens[0].replace("0x", "").replace("0X", "")
        if len(compact) > 2 and len(compact) % 2 == 0:
            tokens = [compact[index : index + 2] for index in range(0, len(compact), 2)]
    values: list[int] = []
    masks: list[int] = []
    for token in tokens:
        token = token.strip()
        if token.lower().startswith("0x"):
            token = token[2:]
        if token in {"?", "??", "**"}:
            values.append(0)
            masks.append(0)
            continue
        if len(token) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", token):
            raise ValueError(f"pattern token must be a byte or ?? wildcard: {token!r}")
        values.append(int(token, 16))
        masks.append(0xFF)
    if not values:
        raise ValueError("pattern cannot be empty")
    if mask is not None:
        mask_bytes = parse_hex_bytes(mask)
        if len(mask_bytes) != len(values):
            raise ValueError("mask length must equal pattern length")
        masks = list(mask_bytes)
    return BytePattern(tuple(values), tuple(masks))


def parse_range(values: Iterable[str]) -> tuple[int, int]:
    items = list(values)
    if len(items) == 1:
        match = re.fullmatch(r"\s*(0x[0-9a-fA-F]+|[0-9]+)\s*[:,-]\s*(0x[0-9a-fA-F]+|[0-9]+)\s*", items[0])
        if not match:
            raise ValueError("range must be START END or START:END")
        start, end = parse_int(match.group(1)), parse_int(match.group(2))
    elif len(items) == 2:
        start, end = parse_int(items[0]), parse_int(items[1])
    else:
        raise ValueError("range must be START END or START:END")
    if end <= start:
        raise ValueError("range end must be greater than range start")
    if start < 0 or end > (1 << 64):
        raise ValueError("range must stay within unsigned 64-bit addresses")
    return start, end


def select_function_addresses(
    connection: sqlite3.Connection,
    *,
    all_functions: bool = False,
    address: str | None = None,
    address_range: Iterable[str] | None = None,
    name: str | None = None,
    addresses: Iterable[str] | None = None,
) -> list[int]:
    selectors = sum(value is not None for value in (address, address_range, name, addresses)) + int(all_functions)
    if selectors != 1:
        raise ValueError("choose exactly one of --all, --address, --addresses, --range, or --name")
    if addresses is not None:
        selected = sorted({ea for value in addresses for ea in select_function_addresses(connection, address=value)})
        if not selected:
            raise ValueError("function selector matched no functions")
        return selected
    function_rows = connection.execute("SELECT start_ea, end_ea, name, demangled_name FROM functions").fetchall()
    functions = [
        {"start": ida_ea(row["start_ea"]), "end": ida_ea(row["end_ea"]), "name": row["name"], "demangled": row["demangled_name"]}
        for row in function_rows
    ]
    if all_functions:
        addresses = sorted(item["start"] for item in functions)
    elif address is not None:
        ea = parse_int(address)
        addresses = [item["start"] for item in functions if item["start"] <= ea < item["end"]]
        if not addresses:
            block_rows = connection.execute("SELECT function_ea, start_ea, end_ea FROM basic_blocks").fetchall()
            addresses = [ida_ea(row["function_ea"]) for row in block_rows if ida_ea(row["start_ea"]) <= ea < ida_ea(row["end_ea"])]
    elif address_range is not None:
        start, end = parse_range(address_range)
        addresses = [item["start"] for item in functions if item["start"] < end and item["end"] > start]
        block_rows = connection.execute("SELECT function_ea, start_ea, end_ea FROM basic_blocks").fetchall()
        addresses.extend(
            ida_ea(row["function_ea"])
            for row in block_rows
            if ida_ea(row["start_ea"]) < end and ida_ea(row["end_ea"]) > start
        )
    else:
        assert name is not None
        folded = name.casefold()
        addresses = [item["start"] for item in functions if item["name"].casefold() == folded or (item["demangled"] or "").casefold() == folded]
    addresses = sorted(set(addresses))
    if not addresses:
        raise ValueError("function selector matched no functions")
    return addresses


def selection_preview(connection, *, limit=100, max_functions=0, **selectors):
    """Explain scope without starting IDA; budget check happens before export."""
    if limit < 0 or max_functions < 0:
        raise ValueError('selection limits must be non-negative')
    selected = select_function_addresses(connection, **selectors)
    address_range = selectors.get('address_range')
    bounds = parse_range(address_range) if address_range else None
    points = [parse_int(v) for v in (selectors.get('addresses') or [])]
    if selectors.get('address') is not None:
        points.append(parse_int(selectors['address']))
    rows = {ida_ea(r['start_ea']):r for r in connection.execute('SELECT start_ea,end_ea,name FROM functions')}
    items = []
    for ea in selected[:limit] if limit else selected:
        row = rows[ea]
        end = ida_ea(row['end_ea'])
        reasons = []
        if bounds:
            if bounds[0] <= ea < bounds[1]:
                reasons.append('entry_in_range')
            elif ea < bounds[1] and end > bounds[0]:
                reasons.append('body_range_overlap')
            else:
                reasons.append('cfg_overlap_outside_entry_range')
        elif points:
            reasons.append('entry_address' if ea in points else
                           'body_contains_address' if any(ea <= p < end for p in points) else 'cfg_contains_address')
        else:
            reasons.append('all' if selectors.get('all_functions') else 'name')
        items.append(dict(address=ea,address_hex=f'0x{ea:X}',name=row['name'],reasons=reasons))
    return dict(function_count=len(selected),max_functions=max_functions,
                budget_exceeded=bool(max_functions and len(selected)>max_functions),
                truncated=bool(limit and len(selected)>limit),functions=items)

