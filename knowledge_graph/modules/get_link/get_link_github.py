import os
import time
import logging
import requests
import argparse
import sys
from datetime import datetime
from pathlib import Path

try:
    from modules.utils.paths import METADATA_DIR, ensure_data_dirs
except ModuleNotFoundError:
    # Allow direct execution from this file path.
    SBOM_ROOT = Path(__file__).resolve().parents[2]
    if str(SBOM_ROOT) not in sys.path:
        sys.path.insert(0, str(SBOM_ROOT))
    from modules.utils.paths import METADATA_DIR, ensure_data_dirs

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SEARCH_URL = "https://api.github.com/search/repositories"

TARGET_PER_LANGUAGE = 20
MIN_SIZE_KB = 10000
MAX_SIZE_KB = 20000
MIN_STARS = 100

BLACKLIST_KEYWORDS = [
    "awesome", "tutorial", "example", "demo",
    "boilerplate", "starter", "template",
    "learning", "course", "sample"
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

COMBINED_FILE = METADATA_DIR / "repos_link.txt"
SECTION_HEADERS = {
    "JavaScript": "# NodeJS - JavaScript, TypeScript",
    "Python": "# Python",
}


# ========================
# REQUEST
# ========================

def headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }


def request_get(url, params=None):
    while True:
        r = requests.get(url, headers=headers(), params=params, timeout=30)
        if r.status_code == 200:
            return r
        if r.status_code in (403, 429):
            reset = int(r.headers.get("X-RateLimit-Reset", 0))
            sleep_time = max(reset - int(time.time()), 0) + 5
            logging.warning(f"Rate limit hit. Sleep {sleep_time}s")
            time.sleep(sleep_time)
        else:
            logging.warning(f"Request failed: {r.status_code}")
            return None


# ========================
# FILTER
# ========================

def is_blacklisted(text):
    if not text:
        return False
    text = text.lower()
    return any(k in text for k in BLACKLIST_KEYWORDS)


def has_dependency_file(owner, repo, language):
    files = {
        "JavaScript": ["package.json"],
        "Python": ["requirements.txt", "setup.py", "pyproject.toml"]
    }

    for f in files.get(language, []):
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{f}"
        r = request_get(url)
        if r:
            return True
    return False


# ========================
# SEARCH
# ========================

def search(language, page):
    query = (
        f"language:{language} "
        f"size:{MIN_SIZE_KB}..{MAX_SIZE_KB} "
        f"stars:>={MIN_STARS} "
        "fork:false archived:false"
    )

    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": 50,
        "page": page
    }

    r = request_get(SEARCH_URL, params=params)
    if not r:
        return []

    return r.json().get("items", [])


# ========================
# COMBINED FILE UTILS
# ========================

def ensure_combined_file():
    ensure_data_dirs()

    if COMBINED_FILE.exists():
        return

    with COMBINED_FILE.open("w", encoding="utf-8") as f:
        f.write("# NodeJS - JavaScript, TypeScript\n\n")
        f.write("# Python\n\n")


def is_repo_url(line):
    return line.startswith("https://github.com/")


def normalize_repo_url(url):
    if not url:
        return ""

    normalized = str(url).strip().replace("\\", "/")
    if not normalized:
        return ""

    if not normalized.lower().startswith("https://github.com/"):
        return ""

    return normalized.rstrip("/")


def canonical_repo_url(url):
    if not url:
        return ""

    normalized = str(url).strip().replace("\\", "/")
    if not normalized:
        return ""

    if not normalized.lower().startswith("https://github.com/"):
        return ""

    return normalized.rstrip("/")


def load_existing_urls(language):
    """Load existing URLs from the matching section in repos-link.txt."""
    ensure_combined_file()

    target_header = SECTION_HEADERS[language]
    other_header = SECTION_HEADERS["Python" if language == "JavaScript" else "JavaScript"]

    in_target = False
    urls = set()

    with COMBINED_FILE.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line == target_header:
                in_target = True
                continue
            if line == other_header:
                in_target = False
                continue

            if in_target:
                normalized = normalize_repo_url(line)
                if normalized:
                    urls.add(normalized)

    return urls


def append_to_combined(language, urls):
    """Append new URLs to the target section with a crawl timestamp."""
    ensure_combined_file()

    # Keep original behavior: deduplicate before writing.
    existing = load_existing_urls(language)
    new_urls = []
    seen_in_batch = set()
    for url in urls:
        canonical = canonical_repo_url(url)
        if not canonical:
            continue

        normalized = normalize_repo_url(canonical)

        if normalized in existing or normalized in seen_in_batch:
            continue
        seen_in_batch.add(normalized)
        new_urls.append(canonical)

    if not new_urls:
        logging.info(f"Added 0 new repos to {COMBINED_FILE} [{language}]")
        return

    target_header = SECTION_HEADERS[language]
    other_header = SECTION_HEADERS["Python" if language == "JavaScript" else "JavaScript"]

    with COMBINED_FILE.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    target_header_idx = None
    section_end_idx = len(lines)

    for idx, raw in enumerate(lines):
        s = raw.strip()
        if s == target_header and target_header_idx is None:
            target_header_idx = idx
            continue

        # End of current section happens when we hit the other header.
        if target_header_idx is not None and s == other_header:
            section_end_idx = idx
            break

    if target_header_idx is None:
        # Recover safely if file headers were edited manually.
        lines.append(f"{target_header}\n")
        lines.append("\n")
        section_end_idx = len(lines)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    block = [f"# Crawled: {timestamp}\n"]
    block.extend(f"{url}\n" for url in new_urls)
    block.append("\n")

    updated_lines = lines[:section_end_idx] + block + lines[section_end_idx:]

    with COMBINED_FILE.open("w", encoding="utf-8") as f:
        f.writelines(updated_lines)

    logging.info(f"Added {len(new_urls)} new repos to {COMBINED_FILE} [{language}]")


# ========================
# CRAWL
# ========================

def crawl(language, existing_urls=None):
    if existing_urls is None:
        existing_urls = set()

    collected = []
    collected_keys = set()
    page = 1

    logging.info(f"=== Crawling {language} ===")

    while len(collected) < TARGET_PER_LANGUAGE:
        repos = search(language, page)
        if not repos:
            break

        for repo in repos:
            if len(collected) >= TARGET_PER_LANGUAGE:
                break

            owner = repo["owner"]["login"]
            name = repo["name"]
            description = repo.get("description", "")
            url = repo["html_url"]

            if is_blacklisted(name) or is_blacklisted(description):
                continue

            if not has_dependency_file(owner, name, language):
                continue

            canonical_url = canonical_repo_url(url)
            if not canonical_url:
                continue

            normalized_url = normalize_repo_url(canonical_url)

            if normalized_url in existing_urls:
                continue

            if normalized_url not in collected_keys:
                collected.append(canonical_url)
                collected_keys.add(normalized_url)
                logging.info(f"{language}: {len(collected)}/{TARGET_PER_LANGUAGE}")

        page += 1

    return collected


# ========================
# ENTRY
# ========================

def get_link_github(crawl_js=False, crawl_py=False):
    if not crawl_js and not crawl_py:
        raise ValueError("Use crawl_js and/or crawl_py")

    if crawl_js:
        js_existing = load_existing_urls("JavaScript")
        js_urls = crawl("JavaScript", js_existing)
        append_to_combined("JavaScript", js_urls)

    if crawl_py:
        py_existing = load_existing_urls("Python")
        py_urls = crawl("Python", py_existing)
        append_to_combined("Python", py_urls)

    logging.info(f"Output file: {COMBINED_FILE}")
    return COMBINED_FILE


def main():
    if not GITHUB_TOKEN:
        logging.error("Set GITHUB_TOKEN first")
        exit(1)

    parser = argparse.ArgumentParser(description="Crawl GitHub repositories (combined output v2)")
    parser.add_argument("-js", action="store_true", help="Crawl JavaScript repositories")
    parser.add_argument("-py", action="store_true", help="Crawl Python repositories")
    args = parser.parse_args()

    if not args.js and not args.py:
        print("Use -js and/or -py")
        exit(1)

    get_link_github(crawl_js=args.js, crawl_py=args.py)


if __name__ == "__main__":
    main()
