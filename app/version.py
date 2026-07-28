"""DracoLure release version."""

from pathlib import Path

__version__ = "1.0.0"

_root = Path(__file__).resolve().parents[1] / "VERSION"
if _root.is_file():
    __version__ = _root.read_text(encoding="utf-8").strip()
