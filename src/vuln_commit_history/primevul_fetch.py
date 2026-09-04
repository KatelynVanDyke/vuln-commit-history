from __future__ import annotations

import zipfile
from pathlib import Path

from .io import read_json

# Dataset is a manual Google Drive download, not a direct file in the DLVulDet/PrimeVul repo.
PRIMEVUL_DOWNLOAD_URL = "https://github.com/DLVulDet/PrimeVul"

PAIRED_JSONL_NAMES = ("primevul_train_paired.jsonl", "primevul_test_paired.jsonl", "primevul_valid_paired.jsonl")
FILE_INFO_NAME = "file_info.json"


class FetchError(RuntimeError):
    pass


def ensure_primevul_raw(raw_dir: str | Path, source_zip: str | Path) -> tuple[list[Path], Path]:
    raw_dir = Path(raw_dir)
    paired_paths = [raw_dir / name for name in PAIRED_JSONL_NAMES]
    source_zip = Path(source_zip)
    missing = [p for p in (*paired_paths, source_zip) if not p.is_file()]
    if missing:
        raise FetchError(
            f"Missing PrimeVul input(s): {[str(p) for p in missing]}. Download PrimeVul_v0.1 from "
            f"the Google Drive link in {PRIMEVUL_DOWNLOAD_URL} (the repo itself only links out), "
            f"then extract primevul_{{train,test,valid}}_paired.jsonl into {raw_dir} and keep the zip at "
            f"{source_zip} for its file_contents/ entries."
        )
    return paired_paths, source_zip


def load_file_info(raw_dir: str | Path) -> dict:
    """func_hash (str) -> {file_name, file_hash, project_file_path, local_file_path,
    start_line, end_line}."""
    return read_json(Path(raw_dir) / FILE_INFO_NAME)


def zip_member_path(file_hash, project: str) -> str:
    return f"PrimeVul_v0.1/file_contents/{project}/{file_hash}.txt"


def read_file_content(zf: zipfile.ZipFile, file_hash, project: str) -> str:
    member = zip_member_path(file_hash, project)
    try:
        return zf.read(member).decode("utf-8", errors="replace")
    except KeyError:
        raise KeyError(f"missing zip member: {member}") from None
