"""Bounded reverse-xref navigation with explicit missing-link frontiers."""
from collections import deque
from .db import ida_ea, sqlite_ea


def import_callers(connection, address, *, max_hops=4, max_nodes=1000, max_edges=5000):
    if not 0 <= address < 1 << 64 or min(max_hops,max_nodes,max_edges) < 1:
        raise ValueError("unsigned address and positive navigation budgets required")
    queue = deque([(address,0)])
    seen = {address}
    edges,callers,frontier = [],{},[]
    while queue:
        ea,depth = queue.popleft()
        if depth >= max_hops:
            frontier.append(dict(address=f"0x{ea:X}",reason="max_hops"))
            continue
        found = False
        rows = connection.execute("SELECT source_ea,source_function_ea,xref_type,is_code FROM xrefs WHERE target_ea=?",(sqlite_ea(ea),))
        for row in rows:
            found = True
            if len(edges) >= max_edges:
                frontier.append(dict(address=f"0x{ea:X}",reason="max_edges"))
                return dict(address=f"0x{address:X}",callers=list(callers.values()),edges=edges,frontier=frontier,truncated=True)
            source = ida_ea(row["source_ea"])
            function = ida_ea(row["source_function_ea"]) if row["source_function_ea"] is not None else None
            edges.append(dict(source=f"0x{source:X}",target=f"0x{ea:X}",xref_type=row["xref_type"],is_code=bool(row["is_code"])))
            # A function mentioning a GOT/PLT node is a referencing function,
            # not automatically a proven call through that import.
            if function is not None:
                callers[function] = dict(function=f"0x{function:X}",via=f"0x{source:X}",interpretation="referencing_function_not_proven_import_call")
            for node in {source,function} - {None}:
                if node in seen:
                    continue
                if len(seen) >= max_nodes:
                    frontier.append(dict(address=f"0x{node:X}",reason="max_nodes"))
                    continue
                seen.add(node)
                queue.append((node,depth+1))
        if not found:
            frontier.append(dict(address=f"0x{ea:X}",reason="no_exported_incoming_xrefs_not_proof_unused"))
    return dict(address=f"0x{address:X}",callers=list(callers.values()),edges=edges,frontier=frontier,
                truncated=any(f["reason"].startswith("max_") for f in frontier))
