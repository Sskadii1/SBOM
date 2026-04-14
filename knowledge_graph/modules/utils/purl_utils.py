from typing import Optional


def parse_purl_type(purl: Optional[str]) -> Optional[str]:
    if not purl or not purl.startswith("pkg:"):
        return None
    try:
        purl_body = purl[4:]
        purl_type = purl_body.split("/", 1)[0]
        return purl_type
    except Exception:
        return None


def infer_ecosystem(purl: Optional[str]) -> Optional[str]:
    purl_type = parse_purl_type(purl)
    if not purl_type:
        return None
    mapping = {
        "npm": "npm",
        "maven": "maven",
        "pypi": "pypi",
        "golang": "go",
        "nuget": "nuget",
        "composer": "composer",
        "gem": "rubygems",
        "cargo": "cargo",
        "github": "github",
    }
    return mapping.get(purl_type, purl_type)


def infer_package_manager(purl: Optional[str]) -> Optional[str]:
    purl_type = parse_purl_type(purl)
    if not purl_type:
        return None
    mapping = {
        "npm": "npm",
        "maven": "maven",
        "pypi": "pip",
        "golang": "go",
        "nuget": "nuget",
        "composer": "composer",
        "gem": "bundler",
        "cargo": "cargo",
    }
    return mapping.get(purl_type, purl_type)
