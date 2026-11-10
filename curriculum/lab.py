"""Offline curriculum answer key. Synthetic checks, never operational approval."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
for base in (ROOT, ROOT / "src", ROOT / "layer-b"):
    sys.path.insert(0, str(base))
CASES = []

def check(name, actual, expected):
    passed = actual == expected
    CASES.append({"case": name, "actual": actual, "expected": expected, "passed": passed})
    if not passed:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")

def rejects(name, call, error=ValueError):
    try:
        call()
    except error:
        check(name, error.__name__, error.__name__)
    else:
        raise AssertionError(f"{name}: expected {error.__name__}")



def definitions(path, names, namespace):
    # Execute selected original AST definitions, excluding provider imports/calls.
    tree = ast.parse((ROOT / path).read_text())
    chosen = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            chosen.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            chosen.append(node)
    found = {n.name for n in chosen if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
    found |= {t.id for n in chosen if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    if found != set(names):
        raise ValueError("Reviewed source definitions changed")
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(ROOT / path), "exec"), namespace)
    return namespace

def run():
    # Extract the existing storage class without importing signature-provider code.
    # This exercises storage/CAS semantics only, not signed-release verification.
    import os
    import sqlite3
    from contextlib import contextmanager
    ns = definitions("src/tect/durable_registry_floor.py", {"RegistryFloorStore"},
                     {"os":os,"sqlite3":sqlite3,"contextmanager":contextmanager})
    Store = ns["RegistryFloorStore"]
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp)/"floor.db")
        s = Store.provision(path,initial_sequence=3)
        check("provisioned floor", s.read(), 3)
        check("matching writer advances", s.compare_and_advance(expected_floor=3,new_sequence=5), True)
        check("stale writer rejected", s.compare_and_advance(expected_floor=3,new_sequence=6), False)
        check("reopening preserves floor", Store(path).read(), 5)
        rejects("rollback rejected", lambda: s.compare_and_advance(expected_floor=5,new_sequence=4))
        rejects("bootstrap refuses existing file", lambda: Store.provision(path,initial_sequence=1), FileExistsError)
    rejects("in-memory reset forbidden", lambda: Store(":memory:"))

if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--verify"]):
        raise SystemExit("Usage: python curriculum/lab.py [--verify]")
    run()
    report = {"schema_version": 1, "status": "PASS", "case_count": len(CASES),
              "cases": CASES, "scope": "Synthetic curriculum checks only"}
    if sys.argv[1:] == ["--verify"]:
        expected = json.loads((Path(__file__).parent / "expected.json").read_text())
        if report != expected:
            raise AssertionError("Observed answers differ from curriculum/expected.json")
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
