"""Render or check the route-registry-derived local HTTP API contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from causal_continuity_engine.api import render_api_document  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    target = ROOT / "docs" / "API.md"
    expected = render_api_document()
    if args.write:
        target.write_text(expected, encoding="utf-8", newline="\n")
        return 0
    if not target.is_file() or target.read_text(encoding="utf-8") != expected:
        print("docs/API.md is stale; run render_api_docs.py --write")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
