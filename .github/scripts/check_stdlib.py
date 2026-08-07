"""Fail when the runtime package imports outside the Python standard library."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def main() -> int:
    stdlib = set(sys.stdlib_module_names)
    offenders: dict[str, set[str]] = {}
    for path in sorted(Path("causal_continuity_engine").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = ([node.module.split(".")[0]]
                         if node.module and not node.level else [])
            else:
                continue
            for name in names:
                if name not in stdlib and name != "causal_continuity_engine":
                    offenders.setdefault(name, set()).add(path.name)
    if offenders:
        for name, files in sorted(offenders.items()):
            joined = ", ".join(sorted(files))
            print(
                "causal_continuity_engine/ imports third-party module "
                f"{name!r} in {joined}",
                file=sys.stderr,
            )
        print("the engine must stay stdlib-only", file=sys.stderr)
        return 1
    print("causal_continuity_engine/ is stdlib-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
