"""Refuse a release that cannot be reproduced from the tagged tree."""

from __future__ import annotations

import subprocess


def main() -> int:
    try:
        status = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            text=True, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("release clean-tree check timed out after 30s") from exc
    if status:
        print("release: working tree is not clean")
        print(status, end="")
        return 1
    print("release tree is clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
