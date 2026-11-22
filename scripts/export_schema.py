"""Export the Finding JSON Schema to docs/finding.schema.json.

Run from the backend environment:  ``cd backend && uv run python ../scripts/export_schema.py``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.models.finding import Finding  # noqa: E402

OUT = ROOT / "docs" / "finding.schema.json"


def main() -> None:
    """Write the schema with stable formatting."""
    schema = json.dumps(Finding.model_json_schema(), indent=2, sort_keys=True) + "\n"
    OUT.write_text(schema, encoding="utf-8", newline="\n")
    sys.stdout.write(f"wrote {OUT.relative_to(ROOT)}\n")


if __name__ == "__main__":
    main()
