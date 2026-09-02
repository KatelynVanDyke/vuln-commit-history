from __future__ import annotations

from pathlib import Path

from . import git_ops
from .constants import FIX, OTHER, PROVENANCE_NATURAL_HISTORY, SLICE_OFFSET, TRANSITION_LABEL
from .io import read_jsonl, write_jsonl


def build_history_window(
    repository: Path,
    anchor: dict,
    window_size: int,
) -> list[dict]:
    if not anchor["file_paths"]:
        return []
    primary_file = anchor["file_paths"][0]
    parent = anchor["parent_commit_hash"]
    fix = anchor["fix_commit_hash"]

    touching = git_ops.file_history(repository, parent, primary_file, max_count=window_size + 1)
    if touching and touching[-1] == parent:
        prior_commits = touching
    else:
        prior_commits = touching[-window_size:] + [parent]

    full_sequence = prior_commits + [fix]
    last_index = len(full_sequence) - 1

    transitions: list[dict] = []
    for index in range(1, len(full_sequence)):
        source_commit = full_sequence[index - 1]
        target_commit = full_sequence[index]
        offset = index - last_index
        transitions.append(
            {
                "sample_id": f"{anchor['anchor_id']}_t{offset}",
                "anchor_id": anchor["anchor_id"],
                "project": anchor["project"],
                "clone_url": anchor["clone_url"],
                "file_path": primary_file,
                "source_commit": source_commit,
                "target_commit": target_commit,
                "cve_ids": anchor["cve_ids"],
                "provenance": PROVENANCE_NATURAL_HISTORY,
                SLICE_OFFSET: offset,
                TRANSITION_LABEL: FIX if offset == 0 else OTHER,
            }
        )
    return transitions


def build_all_history_windows(
    anchors_path: str | Path,
    repositories_dir: str | Path,
    output_path: str | Path,
    window_size: int = 10,
    clone_missing: bool = False,
) -> dict:
    anchors = read_jsonl(anchors_path)
    repositories_root = Path(repositories_dir)
    all_transitions: list[dict] = []
    report = {"anchors_processed": 0, "anchors_failed": []}

    for anchor in anchors:
        try:
            repository = git_ops.repo_directory(repositories_root, anchor["project"], anchor["clone_url"])
            git_ops.ensure_repository(repository, anchor["clone_url"], clone_missing)
            git_ops.ensure_revision(repository, anchor["parent_commit_hash"])
            git_ops.ensure_revision(repository, anchor["fix_commit_hash"])
            transitions = build_history_window(repository, anchor, window_size)
            if not transitions:
                raise ValueError("Empty history window")
            for transition in transitions:
                transition["source_timestamp"] = git_ops.commit_timestamp(repository, transition["source_commit"])
                transition["target_timestamp"] = git_ops.commit_timestamp(repository, transition["target_commit"])
            all_transitions.extend(transitions)
            report["anchors_processed"] += 1
        except Exception as exc:
            report["anchors_failed"].append({"anchor_id": anchor["anchor_id"], "error": str(exc)})

    write_jsonl(output_path, all_transitions)
    report["transitions"] = len(all_transitions)
    return report
