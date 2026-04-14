import os
from pathlib import Path
from typing import Optional


BASE_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BASE_DIR  # public alias for other modules
DATA_DIR = BASE_DIR / "data"

REPOS_DIR = DATA_DIR / "repos"
METADATA_DIR = DATA_DIR / "metadata"
REPOS_METADATA_FILE = METADATA_DIR / "repos_metadata.json"

SBOMS_DIR = DATA_DIR / "sboms"
VULNS_DIR = DATA_DIR / "vulnerabilities"

VULNERABLE_REPOS_DIR = DATA_DIR / "vulnerable_repos"
VULNERABLE_REPOS_METADATA_FILE = METADATA_DIR / "vulnerable_repos_metadata.json"
VULNERABLE_SBOMS_DIR = DATA_DIR / "vulnerable_sboms"
VULNERABLE_VULNS_DIR = DATA_DIR / "vulnerable_vulnerabilities"


def ensure_data_dirs() -> None:
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    SBOMS_DIR.mkdir(parents=True, exist_ok=True)
    VULNS_DIR.mkdir(parents=True, exist_ok=True)
    VULNERABLE_REPOS_DIR.mkdir(parents=True, exist_ok=True)
    VULNERABLE_SBOMS_DIR.mkdir(parents=True, exist_ok=True)
    VULNERABLE_VULNS_DIR.mkdir(parents=True, exist_ok=True)


def to_project_relative(path_value: Optional[str]) -> Optional[str]:
    """
    Convert a path to a project-relative path when possible.
    Falls back to the original value if conversion is not possible.
    """
    if not path_value:
        return path_value

    raw = str(path_value).strip()
    if not raw:
        return raw

    normalized = raw.replace("\\", "/")
    looks_absolute = Path(raw).is_absolute() or normalized.startswith("/")

    if looks_absolute:
        try:
            return str(Path(raw).resolve().relative_to(BASE_DIR.resolve())).replace("\\", "/")
        except Exception:
            marker = "/data/"
            idx = normalized.find(marker)
            if idx >= 0:
                return normalized[idx + 1 :]
            return raw

    return normalized


def resolve_project_path(path_value: Optional[str]) -> Optional[str]:
    """
    Resolve metadata path values to a usable absolute path in the current environment.
    Supports both project-relative and legacy absolute paths.
    """
    if not path_value:
        return path_value

    raw = str(path_value).strip()
    if not raw:
        return raw

    normalized = raw.replace("\\", "/")
    looks_absolute = Path(raw).is_absolute() or normalized.startswith("/")
    candidate = Path(raw)

    if looks_absolute:
        if candidate.exists():
            return str(candidate)
        rel = to_project_relative(raw)
        if rel:
            rebased = BASE_DIR / rel
            if rebased.exists():
                return str(rebased)
        return str(candidate)

    rebased = BASE_DIR / raw
    return str(rebased)
