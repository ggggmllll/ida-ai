"""Pure helpers for preserving microcode CFG and value-number locations.

The Hex-Rays Python objects are only available inside IDA.  Keeping the
normalisation here independent of IDA makes the exported contract testable
with small fixtures and keeps the SQLite client from having to reconstruct
relationships from formatted microcode text.
"""

from __future__ import annotations

from typing import Any, Iterable


def _walk(value: Any, path: str) -> Iterable[tuple[str, dict[str, Any]]]:
    if not isinstance(value, dict):
        return
    yield path, value
    kind = value.get("kind")
    if kind == "nested":
        instruction = value.get("instruction")
        if isinstance(instruction, dict):
            for key in ("l", "r"):
                child = instruction.get(key)
                if isinstance(child, dict):
                    yield from _walk(child, f"{path}.instruction.{key}")
    elif kind == "address":
        child = value.get("operand")
        if isinstance(child, dict):
            yield from _walk(child, f"{path}.operand")
    elif kind == "arglist":
        for index, child in enumerate(value.get("arguments", [])):
            if isinstance(child, dict):
                yield from _walk(child, f"{path}.arguments[{index}]")
    elif kind == "pair":
        for key in ("low", "high"):
            child = value.get(key)
            if isinstance(child, dict):
                yield from _walk(child, f"{path}.{key}")


def _value_number(value: dict[str, Any]) -> int | None:
    number = value.get("value_number")
    return int(number) if isinstance(number, int) else None


def _has_truncated(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("truncated")) or any(_has_truncated(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_truncated(child) for child in value)
    return False


def _locator(instruction: dict[str, Any]) -> dict[str, Any]:
    return {
        "block_serial": int(instruction["block_serial"]),
        "ordinal": int(instruction["ordinal"]),
        "ea": instruction.get("ea"),
    }


def build_relations(instructions: list[dict[str, Any]], blocks: list[dict[str, Any]]) -> dict[str, Any]:
    """Build conservative value-number def/use edges and CFG metadata.

    Value numbers are recorded only on direct register destinations/uses.
    The output records locations, not reaching-definition edges. Cross-block
    reaching definitions are intentionally left to a separate bounded query.
    ``truncated`` identifies incomplete operand trees.
    """

    definition_occurrences: list[dict[str, Any]] = []
    use_occurrences: list[dict[str, Any]] = []
    truncated = any(_has_truncated(instruction) for instruction in instructions)
    for instruction in instructions:
        destination = instruction.get("d", {})
        value_number = _value_number(destination)
        if destination.get("kind") == "register" and value_number is not None:
            occurrence = {"value_number": value_number, "locator": _locator(instruction),
                          "operand_path": "d"}
            definition_occurrences.append(occurrence)

    for instruction in instructions:
        use = _locator(instruction)
        for root in ("l", "r"):
            for path, operand in _walk(instruction.get(root, {}), root):
                value_number = _value_number(operand)
                if value_number is None or operand.get("kind") != "register":
                    continue
                use_occurrences.append({"value_number": value_number, "locator": use,
                                        "operand_path": path})

    normalized_blocks = []
    cfg_complete = bool(blocks)
    block_serials = {int(block["serial"]) for block in blocks}
    if len(block_serials) != len(blocks):
        cfg_complete = False
    for block in blocks:
        predecessors = block.get("predecessors")
        successors = block.get("successors")
        if predecessors is None or successors is None:
            cfg_complete = False
        normalized_blocks.append({
            "serial": int(block["serial"]),
            "predecessors": None if predecessors is None else [int(value) for value in predecessors],
            "successors": None if successors is None else [int(value) for value in successors],
            **({key: block[key] for key in ("start_ea", "end_ea", "instruction_count") if key in block}),
        })
        if any(int(value) not in block_serials for value in (predecessors or [])):
            cfg_complete = False
        if any(int(value) not in block_serials for value in (successors or [])):
            cfg_complete = False

    edges = set()
    for block in normalized_blocks:
        for predecessor in (block["predecessors"] or []):
            edges.add((predecessor, block["serial"]))
    reported_edges = set(edges)
    reported_successors = {(block["serial"], successor) for block in normalized_blocks
                           for successor in (block["successors"] or [])}
    if reported_edges != reported_successors:
        cfg_complete = False

    return {
        "version": 2,
        "cfg": {"complete": cfg_complete, "blocks": normalized_blocks,
                "edges": [{"source": source, "target": target} for source, target in sorted(edges)]},
        "def_use": {"complete_for_exported_register_value_numbers": not truncated,
                     "coverage": "direct register operands carrying a Hex-Rays value_number",
                     "cross_block_reaching_definitions": False,
                     "definitions": definition_occurrences,
                     "uses": use_occurrences,
                     "definition_count": len(definition_occurrences),
                     "use_count": len(use_occurrences)},
        "truncated": truncated,
    }

