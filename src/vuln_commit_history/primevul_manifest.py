from __future__ import annotations

import ast
import difflib
import random
import re
import zipfile
from collections import defaultdict
from pathlib import Path

from . import git_ops, primevul_fetch
from .constants import PROVENANCE_PRIMEVUL_PAIRED
from .io import read_jsonl, stable_id

C_EXTENSIONS = (".c", ".h")
MACRO_PATTERN = re.compile(r"^\s*#\s*(if|ifdef|ifndef|define|endif|elif|else)\b")


def parse_cwe(raw) -> list[str]:
    if isinstance(raw, list):
        return raw
    try:
        parsed = ast.literal_eval(raw)
        return list(parsed) if isinstance(parsed, list) else [str(parsed)]
    except (ValueError, SyntaxError):
        return []


def load_paired_records(paired_paths: list[str | Path]) -> list[dict]:
    records = []
    for path in paired_paths:
        records.extend(read_jsonl(path))
    return records


def _diff_changed_lines(source: str, target: str) -> list[str]:
    source_lines, target_lines = source.splitlines(), target.splitlines()
    matcher = difflib.SequenceMatcher(None, source_lines, target_lines)
    changed = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "equal":
            changed.extend(source_lines[i1:i2])
            changed.extend(target_lines[j1:j2])
    return changed


def size_bucket(diff_size: int) -> str:
    if diff_size <= 5:
        return "small"
    if diff_size <= 25:
        return "medium"
    return "large"


def _file_path(record: dict, file_info: dict | None) -> str:
    if not file_info:
        return record["file_name"]
    info = file_info.get(str(record["func_hash"]))
    return info["project_file_path"] if info else record["file_name"]


def build_pairs(
    records: list[dict], zf: zipfile.ZipFile, file_info: dict | None = None
) -> tuple[list[dict], list[dict]]:
    c_records = [r for r in records if r["file_name"].lower().endswith(C_EXTENSIONS)]
    groups: dict[tuple[str, str], dict[int, list[dict]]] = defaultdict(lambda: {0: [], 1: []})
    for r in c_records:
        groups[(r["commit_id"], r["file_name"])][int(r["target"])].append(r)

    pairs, excluded = [], []
    for (commit_id, file_name), by_target in groups.items():
        vulns, fixes = by_target[1], by_target[0]
        if not vulns or not fixes:
            continue  # can't diff without both sides

        candidates = []
        for vi, v in enumerate(vulns):
            for fi, f in enumerate(fixes):
                ratio = difflib.SequenceMatcher(None, v["func"], f["func"]).quick_ratio()
                candidates.append((ratio, vi, fi))
        candidates.sort(reverse=True)
        used_v, used_f = set(), set()
        for ratio, vi, fi in candidates:
            if vi in used_v or fi in used_f:
                continue
            used_v.add(vi)
            used_f.add(fi)
            v, f = vulns[vi], fixes[fi]

            if v["file_hash"] == f["file_hash"]:
                excluded.append({"reason": "identical_file_hash", "sample_id": f"{v['func_hash']}__{f['func_hash']}"})
                continue
            try:
                source_text = primevul_fetch.read_file_content(zf, v["file_hash"], v["project"])
                target_text = primevul_fetch.read_file_content(zf, f["file_hash"], f["project"])
            except KeyError:
                excluded.append({"reason": "missing_zip_member", "sample_id": f"{v['func_hash']}__{f['func_hash']}"})
                continue
            if source_text == target_text:
                excluded.append({"reason": "identical_file_content", "sample_id": f"{v['func_hash']}__{f['func_hash']}"})
                continue

            changed_lines = _diff_changed_lines(source_text, target_text)
            diff_size = len(changed_lines)
            cwe = parse_cwe(v["cwe"])
            pairs.append(
                {
                    "sample_id": f"{v['func_hash']}__{f['func_hash']}",
                    "project": v["project"],
                    "commit_id": commit_id,
                    "commit_url": v["commit_url"],
                    "file_name": file_name,
                    "file_path": _file_path(v, file_info),
                    "cwe": cwe,
                    "cve": v.get("cve", ""),
                    "provenance": PROVENANCE_PRIMEVUL_PAIRED,
                    "similarity": ratio,
                    "diff_size": diff_size,
                    "size_bucket": size_bucket(diff_size),
                    "has_macro": any(MACRO_PATTERN.match(line) for line in changed_lines),
                    "primary_cwe": cwe[0] if cwe else "UNKNOWN",
                    "vuln_func_hash": v["func_hash"],
                    "vuln_file_hash": v["file_hash"],
                    "fixed_func_hash": f["func_hash"],
                    "fixed_file_hash": f["file_hash"],
                }
            )
    return pairs, excluded


def stratified_sample(
    pairs: list[dict], max_cwes: int = 6, per_cwe: int = 5, min_cwe_pool: int = 3, seed: int = 20260902
) -> list[dict]:
    """One pair per size bucket within each of the top-N CWEs, topped up to per_cwe."""
    rng = random.Random(seed)
    by_cwe = defaultdict(list)
    for p in pairs:
        by_cwe[p["primary_cwe"]].append(p)

    eligible = sorted((c for c, ps in by_cwe.items() if len(ps) >= min_cwe_pool), key=lambda c: -len(by_cwe[c]))
    target_cwes = eligible[:max_cwes]

    selected: list[dict] = []
    seen_ids: set[str] = set()
    for cwe in target_cwes:
        pool = by_cwe[cwe]
        for bucket in ("small", "medium", "large"):
            bucket_pool = [p for p in pool if p["size_bucket"] == bucket and p["sample_id"] not in seen_ids]
            if bucket_pool:
                choice = rng.choice(bucket_pool)
                selected.append(choice)
                seen_ids.add(choice["sample_id"])
        remaining = [p for p in pool if p["sample_id"] not in seen_ids]
        rng.shuffle(remaining)
        for p in remaining:
            if sum(1 for s in selected if s["primary_cwe"] == cwe) >= per_cwe:
                break
            selected.append(p)
            seen_ids.add(p["sample_id"])
    return selected


def build_anchors(
    pairs: list[dict], repositories_dir: str | Path, clone_missing: bool = True
) -> tuple[list[dict], list[dict]]:
    """Reshape PrimeVul pairs into MegaVul's anchor schema so history.py's window-building
    works unmodified."""
    grouped: dict[tuple[str, str], dict] = defaultdict(lambda: {"file_paths": set(), "cve_ids": set(), "commit_url": ""})
    for pair in pairs:
        item = grouped[(pair["project"], pair["commit_id"])]
        item["file_paths"].add(pair.get("file_path") or pair["file_name"])
        if pair.get("cve"):
            item["cve_ids"].add(pair["cve"])
        item["commit_url"] = pair["commit_url"]

    repositories_root = Path(repositories_dir)
    anchors, failed = [], []
    for (project, commit_id), item in sorted(grouped.items()):
        try:
            clone_url = git_ops.clone_url_from_commit_url(item["commit_url"], project)
            repository = git_ops.repo_directory(repositories_root, project, clone_url)
            git_ops.ensure_repository(repository, clone_url, clone_missing)
            git_ops.ensure_revision(repository, commit_id)
            parent_commit_hash = git_ops.parent_commit(repository, commit_id)
            anchors.append(
                {
                    "anchor_id": stable_id(project, commit_id),
                    "project": project,
                    "clone_url": clone_url,
                    "fix_commit_hash": commit_id,
                    "parent_commit_hash": parent_commit_hash,
                    "cve_ids": sorted(item["cve_ids"]),
                    "file_paths": sorted(item["file_paths"]),
                }
            )
        except Exception as exc:
            failed.append({"project": project, "commit_id": commit_id, "error": str(exc)})
    return anchors, failed
