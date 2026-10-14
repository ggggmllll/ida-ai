"""Conservative function classifications shared by IDA export and tests."""

from __future__ import annotations

from collections.abc import Iterable


def is_nullstub_sequence(instructions: Iterable[tuple[str, bool]]) -> bool:
    """Recognize a single return preceded only by harmless entry instructions.

    The boolean is IDA's processor-specific literal-return verdict. A function
    with side effects, branches, data items, or no return is never accepted.
    """
    items = list(instructions)
    harmless_entry = {"nop", "endbr32", "endbr64", "bti"}
    return bool(items) and items[-1][1] and all(
        not is_return and mnemonic.casefold() in harmless_entry
        for mnemonic, is_return in items[:-1]
    )
