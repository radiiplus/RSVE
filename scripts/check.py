"""Check that declared direct Python dependencies match the lockfile."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def normalize(requirement: str) -> str:
    return re.split(r"[<>=!~ ]", requirement, maxsplit=1)[0].lower().replace("_", "-")


manifest = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
declared = {normalize(item) for item in manifest["project"].get("dependencies", ())}
locked = {
    normalize(line.strip())
    for line in (ROOT / "lock").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
if declared != locked:
    raise SystemExit(f"dependency/lock mismatch: declared={sorted(declared)} locked={sorted(locked)}")
print(f"dependency lock consistent: {len(declared)} direct package(s)")
