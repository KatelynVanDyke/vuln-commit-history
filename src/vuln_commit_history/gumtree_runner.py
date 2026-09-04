from __future__ import annotations

import concurrent.futures
import subprocess
from collections import defaultdict
from pathlib import Path

from . import gumtree_classify
from .io import read_jsonl, write_json

ACTION_KINDS = gumtree_classify.ACTION_KINDS


def parse_action_counts(textdiff_output: str) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for line in textdiff_output.splitlines():
        stripped = line.strip()
        if stripped in ACTION_KINDS:
            counts[stripped] += 1
    return dict(counts)


def _analyze_one(
    sample: dict,
    pairs_dir: Path,
    output_dir: Path,
    gumtree_jar: Path,
    java: str,
    source_filename: str,
    target_filename: str,
    skip_existing: bool,
    max_actions: int | None,
) -> dict:
    sample_id = sample["sample_id"]
    source_path = pairs_dir / sample_id / source_filename
    target_path = pairs_dir / sample_id / target_filename
    destination = output_dir / sample_id
    textdiff_file = destination / "gumtree_textdiff.txt"
    frequency_file = destination / "change_frequency.json"

    if skip_existing and textdiff_file.is_file() and frequency_file.is_file():
        return {"sample_id": sample_id, "returncode": 0, "status": "succeeded"}

    destination.mkdir(parents=True, exist_ok=True)
    if not source_path.is_file() or not target_path.is_file():
        status = {"sample_id": sample_id, "returncode": -1, "stderr_tail": f"missing input file(s): {source_path}, {target_path}", "status": "failed"}
        write_json(destination / "run_status.json", status)
        return status

    command = [java, "-jar", str(gumtree_jar), "textdiff", str(source_path), str(target_path)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    status = {"sample_id": sample_id, "returncode": result.returncode, "stderr_tail": result.stderr[-4000:]}

    if result.returncode == 0 and not result.stderr.strip():
        textdiff_file.write_text(result.stdout, encoding="utf-8")
        counts = parse_action_counts(result.stdout)
        classified = gumtree_classify.classify_actions(result.stdout)
        total_actions = sum(counts.values())
        write_json(destination / "action_counts.json", {"total_actions": total_actions, **counts})

        if max_actions is not None and sum(classified.values()) > max_actions:
            status["status"] = "failed"
            status["stderr_tail"] = f"exceeded max_actions ({sum(classified.values())} > {max_actions})"
        else:
            write_json(
                frequency_file,
                {"frequencyParent": [{"c": name, "f": str(count)} for name, count in classified.items()]},
            )
            status["status"] = "succeeded"
    else:
        status["status"] = "failed"
    write_json(destination / "run_status.json", status)
    return status


def run_gumtree(
    manifest_path: str | Path,
    pairs_dir: str | Path,
    output_dir: str | Path,
    gumtree_jar: str | Path,
    workers: int = 1,
    java: str = "java",
    source_filename: str = "source.c",
    target_filename: str = "target.c",
    skip_existing: bool = True,
    max_actions: int | None = 10000,
) -> dict:
    manifest = read_jsonl(manifest_path)
    pairs_root, output_root, jar = Path(pairs_dir), Path(output_dir), Path(gumtree_jar)
    if not jar.is_file():
        raise FileNotFoundError(f"GumTree jar not found: {jar}")
    output_root.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [
            executor.submit(
                _analyze_one,
                sample,
                pairs_root,
                output_root,
                jar,
                java,
                source_filename,
                target_filename,
                skip_existing,
                max_actions,
            )
            for sample in manifest
        ]
        statuses = [future.result() for future in concurrent.futures.as_completed(futures)]
    report = {
        "succeeded": sorted((s for s in statuses if s["status"] == "succeeded"), key=lambda x: x["sample_id"]),
        "failed": sorted((s for s in statuses if s["status"] == "failed"), key=lambda x: x["sample_id"]),
    }
    write_json(output_root / "gumtree_report.json", report)
    return report
