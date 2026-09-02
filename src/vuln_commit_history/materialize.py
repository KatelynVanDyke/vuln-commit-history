from __future__ import annotations

from pathlib import Path

from . import git_ops
from .io import read_jsonl, write_json


def materialize_transitions(
    transitions_path: str | Path,
    repositories_dir: str | Path,
    pairs_dir: str | Path,
    clone_missing: bool = False,
) -> dict:
    transitions = read_jsonl(transitions_path)
    repositories_root = Path(repositories_dir)
    pairs_root = Path(pairs_dir)
    pairs_root.mkdir(parents=True, exist_ok=True)
    report = {"materialized": [], "failed": []}

    for transition in transitions:
        sample_id = transition["sample_id"]
        try:
            repository = git_ops.repo_directory(
                repositories_root, transition["project"], transition["clone_url"]
            )
            git_ops.ensure_repository(repository, transition["clone_url"], clone_missing)
            git_ops.ensure_revision(repository, transition["source_commit"])
            git_ops.ensure_revision(repository, transition["target_commit"])

            source = git_ops.read_blob(repository, transition["source_commit"], transition["file_path"])
            target = git_ops.read_blob(repository, transition["target_commit"], transition["file_path"])

            file_root = pairs_root / sample_id / "f0000"
            file_root.mkdir(parents=True, exist_ok=True)
            (file_root / f"{sample_id}_f0000_s.java").write_text(source, encoding="utf-8")
            (file_root / f"{sample_id}_f0000_t.java").write_text(target, encoding="utf-8")
            report["materialized"].append({"sample_id": sample_id})
        except Exception as exc:  # keep a complete exclusion audit, mirroring the sibling repo
            report["failed"].append({"sample_id": sample_id, "error": str(exc)})

    write_json(pairs_root / "materialization_report.json", report)
    return report
