from __future__ import annotations

import zipfile
from pathlib import Path

from . import primevul_fetch
from .io import write_jsonl


def whitespace_perturb(text: str) -> str:
    """Cosmetic-only rewrite: leading-indentation tabs -> spaces, skipping any line inside a
    block comment or containing a quote char."""
    out_lines = []
    in_block_comment = False
    for line in text.splitlines():
        was_in_comment = in_block_comment
        if "/*" in line:
            in_block_comment = line.rfind("/*") > line.rfind("*/")
        risky = was_in_comment or in_block_comment or '"' in line or "'" in line or "//" in line
        if not risky:
            stripped = line.lstrip("\t")
            leading = len(line) - len(stripped)
            line = ("    " * leading) + stripped
        out_lines.append(line)
    return "\n".join(out_lines) + "\n"


def materialize_pairs(manifest: list[dict], source_zip: str | Path, pairs_dir: str | Path) -> dict:
    pairs_root = Path(pairs_dir)
    pairs_root.mkdir(parents=True, exist_ok=True)
    report = {"materialized": [], "failed": []}
    with zipfile.ZipFile(source_zip) as zf:
        for row in manifest:
            try:
                source_text = primevul_fetch.read_file_content(zf, row["vuln_file_hash"], row["project"])
                target_text = primevul_fetch.read_file_content(zf, row["fixed_file_hash"], row["project"])
                sample_dir = pairs_root / row["sample_id"]
                sample_dir.mkdir(parents=True, exist_ok=True)
                (sample_dir / "source.c").write_text(source_text, encoding="utf-8")
                (sample_dir / "target.c").write_text(target_text, encoding="utf-8")
                report["materialized"].append({"sample_id": row["sample_id"]})
            except Exception as exc:
                report["failed"].append({"sample_id": row["sample_id"], "error": str(exc)})
    return report


def materialize_negative_controls(
    manifest: list[dict], source_zip: str | Path, pairs_dir: str | Path, n: int = 2
) -> list[dict]:
    """Identical-file and whitespace-only pairs GumTree should report as zero structural
    edits on."""
    pairs_root = Path(pairs_dir)
    control_rows = []
    with zipfile.ZipFile(source_zip) as zf:
        for i, base in enumerate(manifest[:n]):
            source_text = primevul_fetch.read_file_content(zf, base["vuln_file_hash"], base["project"])

            identical_id = f"control_identical_{i}"
            identical_dir = pairs_root / identical_id
            identical_dir.mkdir(parents=True, exist_ok=True)
            (identical_dir / "source.c").write_text(source_text, encoding="utf-8")
            (identical_dir / "target.c").write_text(source_text, encoding="utf-8")
            control_rows.append({"sample_id": identical_id, "kind": "control_identical", "based_on": base["sample_id"]})

            whitespace_id = f"control_whitespace_{i}"
            whitespace_dir = pairs_root / whitespace_id
            whitespace_dir.mkdir(parents=True, exist_ok=True)
            (whitespace_dir / "source.c").write_text(source_text, encoding="utf-8")
            (whitespace_dir / "target.c").write_text(whitespace_perturb(source_text), encoding="utf-8")
            control_rows.append({"sample_id": whitespace_id, "kind": "control_whitespace", "based_on": base["sample_id"]})
    return control_rows


def write_manifest(manifest: list[dict], control_rows: list[dict], output_path: str | Path) -> None:
    rows = [{**row, "kind": "real"} for row in manifest] + control_rows
    write_jsonl(output_path, rows)
