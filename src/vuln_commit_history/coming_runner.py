from __future__ import annotations

import concurrent.futures
import subprocess
from pathlib import Path

from .io import read_jsonl, write_json


def _analyze_one(
    transition: dict, pairs_dir: Path, output_dir: Path, coming_jar: Path, java: str, skip_existing: bool
) -> dict:
    sample_id = transition["sample_id"]
    location = pairs_dir / sample_id
    destination = output_dir / sample_id
    frequency_file = destination / "change_frequency.json"

    if skip_existing and frequency_file.is_file():
        return {
            "sample_id": sample_id,
            "returncode": 0,
            "output_file": str(frequency_file),
            "stderr_tail": "",
            "status": "succeeded",
        }

    destination.mkdir(parents=True, exist_ok=True)
    command = [
        java,
        "-classpath",
        str(coming_jar),
        "fr.inria.coming.main.ComingMain",
        "-input",
        "files",
        "-location",
        str(location),
        "-mode",
        "diff",
        "-output",
        str(destination),
        "-parameters",
        "MAX_AST_CHANGES_PER_FILE:10000:MIN_AST_CHANGES_PER_FILE:0",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    status = {
        "sample_id": sample_id,
        "returncode": result.returncode,
        "output_file": str(frequency_file),
        "stderr_tail": result.stderr[-4000:],
    }
    status["status"] = "succeeded" if result.returncode == 0 and frequency_file.exists() else "failed"
    write_json(destination / "run_status.json", status)
    return status


def run_coming(
    transitions_path: str | Path,
    pairs_dir: str | Path,
    output_dir: str | Path,
    coming_jar: str | Path,
    workers: int = 1,
    java: str = "java",
    skip_existing: bool = True,
) -> dict:
    transitions = read_jsonl(transitions_path)
    pairs_root, output_root, jar = Path(pairs_dir), Path(output_dir), Path(coming_jar)
    if not jar.is_file():
        raise FileNotFoundError(f"Coming jar not found: {jar}")
    output_root.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [
            executor.submit(_analyze_one, t, pairs_root, output_root, jar, java, skip_existing)
            for t in transitions
        ]
        statuses = [future.result() for future in concurrent.futures.as_completed(futures)]
    report = {
        "succeeded": sorted((s for s in statuses if s["status"] == "succeeded"), key=lambda x: x["sample_id"]),
        "failed": sorted((s for s in statuses if s["status"] == "failed"), key=lambda x: x["sample_id"]),
    }
    write_json(output_root / "coming_report.json", report)
    return report
