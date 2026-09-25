"""Write portpatrol/knowledge_base.json from DEFAULT_ENTRIES.

Run from the repository root: python3 scripts/generate_kb.py [output-path]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from portpatrol.defaults import DEFAULT_ENTRIES  # noqa: E402

DEFAULT_OUT = REPO_ROOT / "portpatrol" / "knowledge_base.json"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    out = Path(argv[0]) if argv else DEFAULT_OUT
    out.write_text(json.dumps(DEFAULT_ENTRIES, indent=2), encoding="utf-8")
    print(f"wrote {out} ({len(DEFAULT_ENTRIES)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
