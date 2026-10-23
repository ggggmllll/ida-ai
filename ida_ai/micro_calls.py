"""Call observations retain their containing instruction and operand path."""
from __future__ import annotations


def iter_calls(instructions, *, indirect_only=False):
    def walk(value, path):
        if isinstance(value, dict):
            if value.get('opcode') in {'call', 'icall'}:
                yield value, path
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    yield from walk(child, f'{path}.{key}' if path else key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from walk(child, f'{path}[{index}]')

    for container in instructions:
        for call, path in walk(container, ''):
            if indirect_only and call['opcode'] != 'icall':
                continue
            yield {**call, 'ea': call.get('ea', container.get('ea')),
                   'block_serial': container['block_serial'], 'ordinal': container['ordinal'],
                   'operand_path': path, 'container_opcode': container['opcode']}
