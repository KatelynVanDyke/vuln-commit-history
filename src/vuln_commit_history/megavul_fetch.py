from __future__ import annotations

from pathlib import Path

# Dataset is a manual download, not part of the MegaVul git repo.
MEGAVUL_DOWNLOAD_URL = "https://1drv.ms/f/s!AtzrzuojQf5sgeISZ9zN_4owVnUn9g"


class FetchError(RuntimeError):
    pass


def ensure_megavul_json(path: str | Path) -> Path:
    resolved = Path(path)
    if not resolved.is_file():
        raise FetchError(
            f"MegaVul dataset JSON not found at {resolved}. Download the release you "
            f"need (megavul.json is the flattened version manifest.py expects) from "
            f"{MEGAVUL_DOWNLOAD_URL} and save it at this path."
        )
    return resolved
