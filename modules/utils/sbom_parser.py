from typing import Dict, List, Tuple, Optional


def get_sbom_metadata(sbom: Dict) -> Dict:
    metadata = sbom.get("metadata", {}) if sbom else {}
    branch = None
    for prop in metadata.get("properties", []) or []:
        name = prop.get("name")
        if name in ("git.branch", "org.cyclonedx.git.branch", "repo.branch"):
            branch = prop.get("value")
            break
    return {
        "serialNumber": sbom.get("serialNumber"),
        "timestamp": metadata.get("timestamp"),
        "component": metadata.get("component", {}),
        "properties": metadata.get("properties", []),
        "tools": metadata.get("tools", []),
        "branch": branch,
    }


def extract_components(sbom: Dict) -> List[Dict]:
    return sbom.get("components", []) if sbom else []


def extract_dependencies(sbom: Dict) -> Dict[str, List[str]]:
    dependencies = {}
    for dep in sbom.get("dependencies", []) if sbom else []:
        ref = dep.get("ref")
        depends_on = dep.get("dependsOn", []) or []
        if ref:
            dependencies[ref] = depends_on
    return dependencies


def build_bom_ref_map(components: List[Dict]) -> Dict[str, Dict]:
    bom_ref_map = {}
    for comp in components:
        bom_ref = comp.get("bom-ref")
        if bom_ref:
            bom_ref_map[bom_ref] = comp
    return bom_ref_map


def compute_dependency_depths(
    dependencies: Dict[str, List[str]],
    root_ref: Optional[str]
) -> Dict[str, int]:
    if not root_ref or root_ref not in dependencies:
        return {}

    depths: Dict[str, int] = {root_ref: 0}
    queue: List[Tuple[str, int]] = [(root_ref, 0)]

    while queue:
        current, depth = queue.pop(0)
        for child in dependencies.get(current, []):
            if child not in depths:
                depths[child] = depth + 1
                queue.append((child, depth + 1))

    return depths


def extract_occurrences(component: Dict) -> List[Dict]:
    evidence = component.get("evidence", {}) if component else {}
    occurrences = evidence.get("occurrences", []) or []
    normalized = []

    for occ in occurrences:
        location = occ.get("location")
        if isinstance(location, str):
            parts = location.split("#")
            path = parts[0]
            line = int(parts[1]) if len(parts) > 1 else None
        else:
            path = location
            line = None

        if path:
            normalized.append({
                "path": path,
                "line": line,
            })

    return normalized
