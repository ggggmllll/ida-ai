"""Bounded, program-point-sensitive memory queries over exported microcode.

This is a deliberately closed subset: unknown aliases, unmodelled writes and
calls stop a path. No source names or analyst type hypotheses establish an edge.
"""
from __future__ import annotations

import json
from collections import defaultdict

from .db import ida_ea, sqlite_ea
from .virtual_tables import (
    _call_arglist, _constant, _instructions_for_function, _key,
    _microcode_relations_for_function, _operand_truncated,
    _walk,
)


class MemoryQuery:
    PURE_OPS = {"nop", "mov", "add", "sub", "mul", "udiv", "sdiv", "umod", "smod", "or",
                "and", "xor", "shl", "shr", "sar", "neg", "bnot", "lnot", "xdu", "xds", "low",
                "high", "ldx", "ret", "goto", "jcnd", "jz", "jnz", "ja", "jae", "jb", "jbe",
                "jg", "jge", "jl", "jle", "setz", "setnz", "setb", "seta", "setae", "setbe"}
    def __init__(self, connection, *, view="microcode", max_hops=6, max_nodes=500,
                 max_edges=4000, max_alternatives=16, max_context=4):
        self.connection, self.view = connection, view
        self.limits = dict(max_hops=max_hops, max_nodes=max_nodes, max_edges=max_edges,
                           max_alternatives=max_alternatives, max_context=max_context)
        if view not in ("microcode", "micro_flow") or min(self.limits.values()) < 1:
            raise ValueError("a supported view and positive memory-query budgets are required")
        # Recursive traversal is also capped independently of user input.
        if max_hops > 64 or max_context > 16:
            raise ValueError("max_hops must be <=64 and max_context <=16")
        self.pointer_size = 8
        from .db import get_metadata
        self.pointer_size = 8 if get_metadata(connection, "bitness", 64) == 64 else 4
        self.functions = {}
        self.nodes = self.edges = 0
        self.truncated = set()
        self.frontier = []
        self.observations = []

    def function(self, ea):
        if ea not in self.functions:
            row = self.connection.execute(f"SELECT * FROM {self.view} WHERE function_ea=?",
                                          (sqlite_ea(ea),)).fetchone()
            if row is None or row["status"] != "ok":
                self.functions[ea] = None
            else:
                instructions = _instructions_for_function(self.connection, ea, self.view)
                blocks = defaultdict(list)
                for ins in instructions:
                    blocks[ins["block_serial"]].append(ins)
                relations = _microcode_relations_for_function(self.connection, ea, row, self.view)
                if (len(instructions) != row["instruction_count"] or
                    any(len(blocks.get(b["serial"], [])) != b["instruction_count"]
                        for b in relations["cfg"]["blocks"])):
                    self.functions[ea] = None
                    return None
                self.functions[ea] = {"row": row, "instructions": instructions, "blocks": blocks,
                    "relations": relations, "cfg": {b["serial"]: b for b in relations["cfg"]["blocks"]}}
        return self.functions[ea]

    def issue(self, code, ea, location, path, **extra):
        item = {"code": code, "function_ea": ea, "view": self.view,
                "block_serial": location[0], "ordinal": location[1], "path": path, **extra}
        if len(self.frontier) < self.limits["max_nodes"]:
            self.frontier.append(item)
        return [{"status": "unknown", "reason": code, **item}]

    def step(self, depth):
        self.nodes += 1
        if depth > self.limits["max_hops"]:
            self.truncated.add("max_hops")
            return False
        if self.nodes > self.limits["max_nodes"]:
            self.truncated.add("max_nodes")
            return False
        return True

    def edge(self):
        self.edges += 1
        if self.edges > self.limits["max_edges"]:
            self.truncated.add("max_edges")
            return False
        return True

    @staticmethod
    def location(ins):
        return int(ins["block_serial"]), int(ins["ordinal"])

    def definitions(self, ea, operand, location):
        """All nearest definitions on predecessor paths; missing/loops stay unknown."""
        key = _key(operand)
        if key is None:
            return None
        f = self.function(ea)
        if f is None:
            return None
        pending = [(location[0], location[1], frozenset())]
        found = []
        while pending:
            block, before, visited = pending.pop()
            if not self.edge() or block in visited:
                return None
            matches = [i for i in f["blocks"].get(block, []) if i["ordinal"] < before
                       and _key(i.get("d", {})) == key and i["opcode"] != "stx"]
            if matches:
                found.append(max(matches, key=lambda i: i["ordinal"]))
                continue
            cfg = f["cfg"].get(block)
            if cfg and f["relations"]["cfg"]["complete"] and cfg["predecessors"]:
                pending.extend((p, 1 << 60, visited | {block}) for p in cfg["predecessors"])
            elif block == location[0] and not f["cfg"]:
                # Incomplete CFG cannot establish an entry live-in.
                return None
            elif cfg and f["relations"]["cfg"]["complete"] and not cfg["predecessors"]:
                found.append(None)
            else:
                return None
            if len(pending) + len(found) > self.limits["max_alternatives"]:
                self.truncated.add("max_alternatives")
                return None
        return found

    def pointer(self, ea, operand, location, depth=0, visited=frozenset()):
        """Canonical value root plus constant projection; never erase dereferences."""
        if depth > 24 or _operand_truncated(operand):
            return None
        if operand.get("size") not in (None, self.pointer_size):
            return None
        kind = operand.get("kind")
        if kind == "local" and operand.get("local_offset", 0) not in (None, 0):
            return None
        if kind == "address":
            inner = operand.get("operand") or {}
            if inner.get("kind") in ("stack", "local", "global"):
                field = {"stack": "stack_offset", "local": "local_index", "global": "address"}[inner["kind"]]
                value = inner.get(field)
                if value is not None:
                    if inner["kind"] == "global":
                        return (("absolute",), int(value))
                    return (("storage", inner["kind"], ea, int(value)), 0)
            return None
        if kind == "number" and isinstance(operand.get("value"), int):
            return (("absolute",), int(operand["value"]))
        if kind == "nested":
            ins = operand.get("instruction") or {}
            op = ins.get("opcode")
            if op in ("add", "sub"):
                left, right = ins.get("l", {}), ins.get("r", {})
                value = _constant(right)
                if value is None and op == "add":
                    left, right = right, left
                    value = _constant(right)
                if value is None:
                    return None
                bits = int(right.get("size") or self.pointer_size) * 8
                if value >= 0 and value & (1 << (bits - 1)):
                    value -= 1 << bits
                base = self.pointer(ea, left, location, depth + 1, visited)
                if base:
                    projection = base[1] + (value if op == "add" else -value)
                    if -(1 << (self.pointer_size * 8 - 1)) <= projection < (1 << (self.pointer_size * 8)):
                        return base[0], projection
            if op == "mov":
                return self.pointer(ea, ins.get("l", {}), location, depth + 1, visited)
            return None
        key = _key(operand)
        if key is None:
            if kind == "global" and isinstance(operand.get("address"), int):
                return (("global_value", int(operand["address"])), 0)
            return None
        state = (key, location)
        if state in visited:
            return None
        defs = self.definitions(ea, operand, location)
        if defs is None:
            return None
        roots = []
        for ins in defs:
            if ins is None:
                roots.append((("entry", ea, *key), 0))
            elif ins.get("d", {}).get("size") not in (None, self.pointer_size):
                return None
            elif ins["opcode"] == "mov":
                source = ins.get("l", {})
                if ins.get("d", {}).get("size") not in (None, self.pointer_size) or source.get("size") not in (None, self.pointer_size):
                    return None
                if source.get("kind") == "nested" and (source.get("instruction") or {}).get("opcode") in ("call", "icall"):
                    roots.append((("definition", ea, ins["block_serial"], ins["ordinal"], *key), 0))
                else:
                    roots.append(self.pointer(ea, source, self.location(ins), depth + 1, visited | {state}))
            elif ins["opcode"] in ("add", "sub"):
                roots.append(self.pointer(ea, {"kind": "nested", "instruction": ins},
                                          self.location(ins), depth + 1, visited | {state}))
            else:
                # A load/call result defines a new value, not the address from which it came.
                roots.append((("definition", ea, ins["block_serial"], ins["ordinal"], *key), 0))
        return roots[0] if roots and roots[0] is not None and all(x == roots[0] for x in roots) else None

    @staticmethod
    def direct_callee(ins):
        if ins.get("opcode") == "mov" and ins.get("l", {}).get("kind") == "nested":
            ins = ins["l"].get("instruction") or {}
        if ins.get("opcode") != "call":
            return None
        from .propagation import _callee
        return _callee(ins)

    def exits(self, ea):
        f = self.function(ea)
        if not f or not f["relations"]["cfg"]["complete"]:
            return []
        # Require one entry and all blocks reachable; detached exports aren't summaries.
        roots = [b for b, cfg in f["cfg"].items() if not cfg["predecessors"]]
        if len(roots) != 1:
            return []
        todo, seen = list(roots), set()
        while todo:
            b = todo.pop()
            if b in seen:
                continue
            seen.add(b)
            todo.extend(f["cfg"][b]["successors"])
        if seen != set(f["cfg"]):
            return []
        return [(b, 1 << 60) for b, cfg in f["cfg"].items() if not cfg["successors"]]

    def _readonly(self, ea):
        f = self.function(ea)
        if not f or not self.exits(ea):
            return False
        # No calls, helper/asm effects or explicit memory writes in the exported body.
        safe = self.PURE_OPS
        for ins in f["instructions"]:
            if not self.edge():
                return False
            if ins["opcode"] not in safe or any(_operand_truncated(ins.get(k)) for k in ("l", "r", "d")):
                return False
            if any(x.get("kind") == "nested" and (x.get("instruction") or {}).get("opcode") not in safe
                   for k in ("l", "r", "d") for x in _walk(ins.get(k, {}))):
                return False
            if ins.get("d", {}).get("kind") in ("global", "stack"):
                return False
        return True

    def _formal(self, ea, index):
        f = self.function(ea)
        if self.view != "micro_flow" or f is None:
            return None
        args = json.loads(f["row"]["arguments_json"] or "[]")
        if (index >= len(args) or args[index].get("local_index") is None or
                args[index].get("size") != self.pointer_size):
            return None
        return {"kind": "local", "local_index": int(args[index]["local_index"]), "size": self.pointer_size}

    def scan(self, ea, operand, offset, location, *, depth=0, context=(), path=(), visited=frozenset(), inherit=False,
             query=None):
        if not self.step(depth):
            return self.issue("budget_exhausted", ea, location, path)
        if len(context) > self.limits["max_context"]:
            self.truncated.add("max_context")
            return self.issue("max_context", ea, location, path)
        f = self.function(ea)
        if not f:
            return self.issue("view_missing_or_error", ea, location, path)
        if query is None:
            root = self.pointer(ea, operand, location)
            if root is None:
                return self.issue("object_identity_unresolved", ea, location, path)
            query = root[0], root[1] + offset
        state = (self.view, ea, query, location, context)
        if state in visited:
            return self.issue("loop_or_recursive_frontier", ea, location, path)
        visited = visited | {state}
        block, before = location
        for ins in reversed(f["blocks"].get(block, [])):
            if ins["ordinal"] >= before:
                continue
            if not self.edge():
                return self.issue("budget_exhausted", ea, self.location(ins), path)
            loc = self.location(ins)
            if any(_operand_truncated(ins.get(k)) for k in ("l", "r", "d")):
                return self.issue("intervening_expression_truncated", ea, loc, path)
            nested_ops = {(x.get("instruction") or {}).get("opcode")
                          for k in ("l", "r", "d") for x in _walk(ins.get(k, {})) if x.get("kind") == "nested"}
            if query[0][:4] == ("definition", ea, block, ins["ordinal"]) and ins["opcode"] in ("call", "icall"):
                return self.returned_source(ea, ins, query[1], depth, context, path, visited)
            if nested_ops - self.PURE_OPS:
                # A returned pointer is followed into the callee at this exact call,
                # rather than crossing its unmodelled effects in the caller.
                if query[0][:4] == ("definition", ea, block, ins["ordinal"]):
                    return self.returned_source(ea, ins, query[1], depth, context, path, visited)
                return self.issue("nested_memory_effect_unresolved", ea, loc, path)
            if ins["opcode"] == "stx":
                address = self.pointer(ea, ins.get("d", {}), loc)
                width = ins.get("l", {}).get("size")
                if address is None:
                    return self.issue("may_alias_store", ea, loc, path, instruction=ins["text"])
                if address[0] == query[0]:
                    if not isinstance(width, int) or width <= 0:
                        return self.issue("store_width_unknown", ea, loc, path)
                    if address[1] + width <= query[1] or query[1] + self.pointer_size <= address[1]:
                        continue
                    if width != self.pointer_size or address[1] != query[1]:
                        return self.issue("partial_overlapping_store", ea, loc, path, store_size=width)
                    value_root = self.pointer(ea, ins.get("l", {}), loc)
                    # A snapshot load of a global pointer is not a constant: its memory
                    # may have changed. Only literal/address arithmetic and lossless copies.
                    value = (value_root[1] if value_root and value_root[0] == ("absolute",) else None)
                    chain = [{"basis": "constant_address_and_lossless_copy", "canonical": value_root}]
                    evidence = {"function_ea": ea, "block_serial": block, "ordinal": ins["ordinal"],
                                "ea": ins.get("ea"), "view": self.view, "path": list(path),
                                "address_point": value, "value_chain": chain, "object_projection": query[1],
                                "status": "observed_reaching_store_under_model"}
                    self.observations.append(evidence)
                    return [evidence]
                # Different locals can share storage; stack/local/absolute views can overlap.
                # Disjointness is only established by non-overlapping ranges of the SAME root above.
                return self.issue("may_alias_store", ea, loc, path, instruction=ins["text"])
            elif ins["opcode"] in ("call", "icall"):
                callee = self.direct_callee(ins)
                if callee is not None and self._readonly(callee):
                    continue
                arglist = _call_arglist(ins)
                matches = []
                for index, arg in enumerate((arglist or {}).get("arguments", [])):
                    argroot = self.pointer(ea, arg, loc)
                    if argroot and argroot[0] == query[0]:
                        matches.append((index, query[1] - argroot[1]))
                if self.view != "micro_flow" or callee is None or len(matches) != 1:
                    return self.issue("call_side_effect_unknown", ea, loc, path, callee=callee,
                                      matching_arguments=len(matches))
                formal = self._formal(callee, matches[0][0])
                exits = self.exits(callee)
                if formal is None or not exits:
                    return self.issue("callee_contract_or_cfg_missing", ea, loc, path, callee=callee)
                if len(exits) > self.limits["max_alternatives"]:
                    self.truncated.add("max_alternatives")
                    return self.issue("max_alternatives", ea, loc, path)
                edge = {"kind": "direct_call_effect", "caller": ea, "callee": callee,
                        "call_ea": ins.get("ea"), "argument_index": matches[0][0], "projection": matches[0][1]}
                results = []
                for exit_loc in exits:
                    found = self.scan(callee, formal, matches[0][1], exit_loc, depth=depth + 1,
                                      context=context + ((ea, block, ins["ordinal"], callee),),
                                      path=path + (edge,), visited=visited, inherit=True,
                                      query=(("entry", callee, "local", formal["local_index"]), matches[0][1]))
                    for item in found:
                        if item["status"] == "inherit":
                            results.extend(self.scan(ea, operand, offset, loc, depth=depth + 1,
                                context=context, path=path + (edge,), visited=visited, inherit=inherit, query=query))
                        else:
                            results.append(item)
                return results
            elif ins["opcode"] not in self.PURE_OPS or ins.get("d", {}).get("kind") in ("global", "stack"):
                return self.issue("unmodelled_memory_effect", ea, loc, path, opcode=ins["opcode"])
        cfg = f["cfg"].get(block)
        if not cfg or not f["relations"]["cfg"]["complete"]:
            return self.issue("cfg_incomplete", ea, location, path)
        preds = cfg["predecessors"]
        if preds:
            if len(preds) > self.limits["max_alternatives"]:
                self.truncated.add("max_alternatives")
                return self.issue("max_alternatives", ea, location, path)
            results = []
            for pred in preds:
                results.extend(self.scan(ea, operand, offset, (pred, 1 << 60), depth=depth + 1,
                    context=context, path=path + ({"kind": "predecessor", "from": block, "to": pred},),
                    visited=visited, inherit=inherit, query=query))
            return results
        if inherit:
            return [{"status": "inherit"}]
        return self.incoming(ea, query, location, depth, context, path, visited)

    def returned_source(self, ea, ins, offset, depth, context, path, visited):
        calls = [(x.get("instruction") or {}) for k in ("l", "r", "d") for x in _walk(ins.get(k, {}))
                 if x.get("kind") == "nested" and (x.get("instruction") or {}).get("opcode") in ("call", "icall")]
        if ins["opcode"] in ("call", "icall"):
            calls.append(ins)
        if self.view != "micro_flow" or len(calls) != 1:
            return self.issue("call_result_origin_unresolved", ea, self.location(ins), path)
        callee = self.direct_callee(calls[0])
        f = self.function(callee) if callee is not None else None
        exits = self.exits(callee) if f else []
        returned = json.loads(f["row"]["return_json"] or "{}") if f else {}
        if not exits or returned.get("local_index") is None or returned.get("size") != self.pointer_size:
            return self.issue("external_or_missing_return_source", ea, self.location(ins), path,
                              callee=callee, allocation_semantics="unknown")
        if len(exits) > self.limits["max_alternatives"]:
            self.truncated.add("max_alternatives")
            return self.issue("max_alternatives", ea, self.location(ins), path)
        edge = {"kind": "return_source", "caller": ea, "callee": callee, "call_ea": ins.get("ea")}
        results = []
        for loc in exits:
            results.extend(self.scan(callee, {"kind": "local", "local_index": returned["local_index"]}, offset,
                loc, depth=depth + 1, context=context + ((ea, ins["block_serial"], ins["ordinal"], callee),),
                path=path + (edge,), visited=visited))
        return results

    def incoming(self, ea, query, location, depth, context, path, visited):
        """At an entry formal, inspect exported direct callers, preserving external frontier."""
        if self.view != "micro_flow":
            return self.issue("entry_object_source_unknown", ea, location, path)
        f = self.function(ea)
        arguments = json.loads(f["row"]["arguments_json"] or "[]")
        indices = [i for i in range(len(arguments)) if self._formal(ea, i) is not None
                   and ("entry", ea, "local", int(arguments[i]["local_index"])) == query[0]]
        if len(indices) != 1:
            return self.issue("object_origin_or_return_unresolved", ea, location, path,
                              object_root=list(query[0]))
        bound = context[-1] if context and context[-1][3] == ea else None
        results = [] if bound else self.issue("external_or_unexported_callers", ea, location, path)
        count = 0
        for row in self.connection.execute("SELECT function_ea FROM micro_flow WHERE status='ok' ORDER BY function_ea"):
            caller = ida_ea(row[0])
            caller_f = self.function(caller)
            for ins in caller_f["instructions"]:
                if not self.edge():
                    return results + self.issue("budget_exhausted", ea, location, path)
                if self.direct_callee(ins) != ea:
                    continue
                if bound and (caller, ins["block_serial"], ins["ordinal"]) != bound[:3]:
                    continue
                args = (_call_arglist(ins) or {}).get("arguments", [])
                if indices[0] >= len(args):
                    continue
                count += 1
                if count > self.limits["max_alternatives"]:
                    self.truncated.add("max_alternatives")
                    return results + self.issue("max_alternatives", ea, location, path)
                edge = {"kind": "caller_actual", "caller": caller, "callee": ea,
                        "call_ea": ins.get("ea"), "argument_index": indices[0]}
                results.extend(self.scan(caller, args[indices[0]], query[1], self.location(ins), depth=depth + 1,
                    context=context[:-1] if bound else context + ((caller, ins["block_serial"], ins["ordinal"], ea),),
                    path=path + (edge,), visited=visited))
        return results or self.issue("bound_callsite_missing", ea, location, path)

    def result(self, ea, pattern):
        chain = pattern.get("definition_chain") or []
        loads = [item for item in chain if item["opcode"] == "ldx"]
        if not loads:
            leaves = self.issue("vptr_load_locator_missing", ea, (0, 0), ())
        else:
            load = loads[0]
            leaves = self.scan(ea, pattern["receiver"], int(pattern["vptr_offset"]),
                               (load["block_serial"], load["ordinal"]))
        history = []
        if loads and self.function(ea):
            load = loads[0]
            point = (load["block_serial"], load["ordinal"])
            root = self.pointer(ea, pattern["receiver"], point)
            if root:
                projection = root[1] + int(pattern["vptr_offset"])
                for item in self.function(ea)["blocks"].get(point[0], []):
                    if item["ordinal"] >= point[1]:
                        continue
                    if not self.edge():
                        break
                    if item["opcode"] == "stx":
                        address = self.pointer(ea, item.get("d", {}), self.location(item))
                        if address == (root[0], projection):
                            value = self.pointer(ea, item.get("l", {}), self.location(item))
                            history.append({"kind": "same_block_store_observation", "function_ea": ea,
                                "block_serial": point[0], "ordinal": item["ordinal"], "ea": item.get("ea"),
                                "width": item.get("l", {}).get("size"),
                                "address_point": value[1] if value and value[0] == ("absolute",) else None})
                    elif item["opcode"] in ("call", "icall"):
                        history.append({"kind": "call_boundary", "function_ea": ea,
                            "block_serial": point[0], "ordinal": item["ordinal"], "callee": self.direct_callee(item)})
        addresses = sorted({x["address_point"] for x in leaves
                            if x.get("address_point") is not None and x["status"].startswith("observed")})
        unknown = any(x["status"] == "unknown" or x.get("address_point") is None for x in leaves)
        return {"view": self.view, "memory_status": "partial" if unknown or self.truncated else "complete_within_model",
                "address_points": addresses, "leaves": leaves, "frontier": self.frontier,
                "phase_observations": self.observations,
                "local_store_history": {"scope": "query block before vptr load only", "events": history,
                    "interpretation": "ordered observations, not constructor/destructor phases or proof that earlier stores reach the load"},
                "budget": {**self.limits, "visited_nodes": self.nodes, "visited_edges": self.edges},
                "truncated": bool(self.truncated), "truncation_reasons": sorted(self.truncated),
                "lifetime": {"status": "unknown", "reason": "stores are program-point observations; allocation, construction/destruction and reuse semantics are not inferred"},
                "assumptions": ["exported microcode faithfully represents memory effects", "calls return normally",
                                "no concurrent or asynchronous modification", "receiver argument ABI role remains a hypothesis"],
                "completeness": "partial", "runtime_reachability_proven": False}
