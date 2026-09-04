from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .git_ops import clone_url_from_commit_url
from .io import read_json, stable_id, write_jsonl


def build_anchor_manifest(megavul_path: str | Path) -> list[dict]:
    payload = read_json(megavul_path)
    if not isinstance(payload, list):
        raise ValueError("Expected flattened MegaVul JSON to contain a top-level list")

    grouped: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"file_paths": set(), "cve_ids": set(), "git_urls": set(), "parents": set()}
    )
    for row in payload:
        file_path = str(row.get("file_path") or "")
        if not file_path.lower().endswith(".java") or not bool(row.get("is_vul")):
            continue
        project = str(row.get("repo_name") or "").strip()
        commit = str(row.get("commit_hash") or "").strip()
        parent = str(row.get("parent_commit_hash") or "").strip()
        if not project or not commit or not parent:
            continue
        item = grouped[(project, commit)]
        item["file_paths"].add(file_path)
        if row.get("cve_id"):
            item["cve_ids"].add(str(row["cve_id"]))
        if row.get("git_url"):
            item["git_urls"].add(str(row["git_url"]))
        item["parents"].add(parent)

    anchors: list[dict] = []
    for (project, commit), item in sorted(grouped.items()):
        if len(item["parents"]) != 1:
            raise ValueError(f"Commit {project}@{commit} has ambiguous parents: {sorted(item['parents'])}")
        parent = next(iter(item["parents"]))
        git_url = sorted(item["git_urls"])[0] if item["git_urls"] else ""
        clone_url = clone_url_from_commit_url(git_url, project)
        anchor_id = stable_id(project, commit)
        anchors.append(
            {
                "anchor_id": anchor_id,
                "project": project,
                "clone_url": clone_url,
                "fix_commit_hash": commit,
                "parent_commit_hash": parent,
                "cve_ids": sorted(item["cve_ids"]),
                "file_paths": sorted(item["file_paths"]),
            }
        )

    if not anchors:
        raise ValueError("No Java vulnerability-fixing anchors were found")
    return anchors


def write_anchor_manifest(megavul_path: str | Path, output_path: str | Path) -> list[dict]:
    anchors = build_anchor_manifest(megavul_path)
    write_jsonl(output_path, anchors)
    return anchors
