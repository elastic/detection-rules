from __future__ import annotations

import sys
from pathlib import Path
import tomllib


def measure(path: Path) -> int:
    with path.open("rb") as f:
        data = tomllib.load(f)
    return len(data["rule"]["note"])


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: measure_note_size.py <toml> [<toml> ...]", file=sys.stderr)
        return 2

    for arg in sys.argv[1:]:
        path = Path(arg)
        print(f"{path}: {measure(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
