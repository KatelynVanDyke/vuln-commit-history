from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path


class GitCommandError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path | None = None, text: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=text, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() if text else result.stderr.decode("utf-8", errors="replace").strip()
        raise GitCommandError(f"Command failed ({result.returncode}): {' '.join(args)}\n{stderr}")
    return result


def repo_directory(repositories_dir: Path, project: str, clone_url: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", project).strip("_") or "repository"
    digest = hashlib.sha256(clone_url.encode("utf-8")).hexdigest()[:10]
    return repositories_dir / f"{safe}_{digest}"


def ensure_repository(repository: Path, clone_url: str, clone_missing: bool = True) -> None:
    if (repository / ".git").is_dir():
        return
    if not clone_missing:
        raise FileNotFoundError(f"Missing local repository {repository}; set clone_missing=True to clone it")
    repository.parent.mkdir(parents=True, exist_ok=True)
    _run(["git", "clone", "--filter=blob:none", "--no-checkout", clone_url, str(repository)])


def ensure_revision(repository: Path, revision: str) -> None:
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=repository, capture_output=True, check=False
    )
    if probe.returncode == 0:
        return
    _run(["git", "fetch", "--no-tags", "origin", revision], cwd=repository)


def read_blob(repository: Path, revision: str, file_path: str) -> str:
    result = _run(["git", "show", f"{revision}:{file_path}"], cwd=repository, text=False)
    return result.stdout.decode("utf-8", errors="replace")


def commit_timestamp(repository: Path, revision: str) -> str:
    result = _run(["git", "show", "-s", "--format=%cI", revision], cwd=repository)
    return result.stdout.strip()


def ensure_all_repositories(anchors: list[dict], repositories_dir: Path, clone_missing: bool = True) -> dict:
    seen: set[tuple[str, str]] = set()
    report = {"cloned_or_present": [], "failed": []}
    for anchor in anchors:
        key = (anchor["project"], anchor["clone_url"])
        if key in seen:
            continue
        seen.add(key)
        repository = repo_directory(repositories_dir, anchor["project"], anchor["clone_url"])
        try:
            ensure_repository(repository, anchor["clone_url"], clone_missing)
            report["cloned_or_present"].append(anchor["project"])
        except Exception as exc:
            report["failed"].append({"project": anchor["project"], "error": str(exc)})
    return report


def file_history(
    repository: Path, revision: str, file_path: str, max_count: int | None = None
) -> list[str]:
    args = ["git", "log", "--format=%H"]
    if max_count is not None:
        args.append(f"-n{max_count}")
    args += [revision, "--", file_path]
    result = _run(args, cwd=repository)
    hashes = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    hashes.reverse()
    return hashes
