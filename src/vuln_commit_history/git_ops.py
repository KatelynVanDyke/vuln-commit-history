from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

_NO_PROMPT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


class GitCommandError(RuntimeError):
    pass


def _gitweb_project(query: str) -> str | None:
    for part in re.split(r"[;&]", query):
        if part.startswith("p="):
            return unquote(part[2:])
    return None


def clone_url_from_commit_url(commit_url: str, repo_name: str) -> str:
    if commit_url:
        parsed = urlsplit(commit_url)
        path = unquote(parsed.path)

        if parsed.netloc.endswith("googlesource.com") and "/+/" in path:
            path = path.split("/+/", 1)[0].rstrip("/")
            return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

        gitweb_project = _gitweb_project(parsed.query)
        if gitweb_project is not None:
            path = "/" + gitweb_project.lstrip("/")
        else:
            for marker in ("/-/commit/", "/commit/", "/commits/"):
                if marker in path:
                    path = path.split(marker, 1)[0]
                    break
            path = path.rstrip("/")

        if parsed.scheme and parsed.netloc and path and path != "/":
            if not path.endswith(".git"):
                path += ".git"
            return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    if repo_name.count("/") == 1:
        return f"https://github.com/{repo_name}.git"

    raise ValueError(f"Cannot derive clone URL for repository {repo_name!r}")


def _run(args: list[str], cwd: Path | None = None, text: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=text, check=False, env=_NO_PROMPT_ENV)
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
    _run(["git", "-c", "credential.helper=", "clone", "--filter=blob:none", "--no-checkout", clone_url, str(repository)])


def ensure_revision(repository: Path, revision: str) -> None:
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=repository, capture_output=True, check=False
    )
    if probe.returncode == 0:
        return
    _run(["git", "-c", "credential.helper=", "fetch", "--no-tags", "origin", revision], cwd=repository)


def read_blob(repository: Path, revision: str, file_path: str) -> str:
    result = _run(["git", "show", f"{revision}:{file_path}"], cwd=repository, text=False)
    return result.stdout.decode("utf-8", errors="replace")


def parent_commit(repository: Path, revision: str) -> str:
    result = _run(["git", "log", "--format=%H", "-n1", f"{revision}^1"], cwd=repository)
    parent = result.stdout.strip()
    if not parent:
        raise GitCommandError(f"{revision} has no parent commit (repository root?)")
    return parent


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
