from collections import deque
from typing import Dict, List, Tuple, Optional, Set


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


def _prune_cdxgen_flat_deps(
    dependencies: Dict[str, List[str]],
    root_ref: Optional[str]
) -> Dict[str, List[str]]:
    """
    cdxgen often flattens ALL transitive deps under root's dependsOn.
    Detect and prune: if a component appears as a child of any non-root
    node, remove it from root's direct children so the real hierarchy
    is preserved.

    Returns a (possibly) pruned copy of the dependencies dict.
    """
    if not root_ref or root_ref not in dependencies:
        return dependencies

    root_children = set(dependencies.get(root_ref, []))
    if not root_children:
        return dependencies

    transitive_children: Set[str] = set()
    for parent, children in dependencies.items():
        if parent == root_ref:
            continue
        for child in children:
            if child in root_children:
                transitive_children.add(child)

    if transitive_children:
        real_direct = [c for c in dependencies[root_ref]
                       if c not in transitive_children]
        return {**dependencies, root_ref: real_direct}

    return dependencies


def _indegree_zero_nodes(
    dependencies: Dict[str, List[str]],
    exclude: Optional[str] = None,
    valid_refs: Optional[Set[str]] = None,
) -> Set[str]:
    """Return nodes with in-degree 0 (no other node points to them).

    If valid_refs is provided, virtual nodes (in-degree=0 but not in valid_refs,
    e.g. workspace sub-project roots) are replaced by their children so the
    real reachable components become the direct-dep candidates.
    """
    indegree: Dict[str, int] = {}
    all_nodes: Set[str] = set()
    for parent, children in dependencies.items():
        all_nodes.add(parent)
        indegree.setdefault(parent, 0)
        for child in children or []:
            all_nodes.add(child)
            indegree[child] = indegree.get(child, 0) + 1

    zero = {n for n in all_nodes if indegree.get(n, 0) == 0 and n != exclude}

    if not valid_refs:
        return zero

    # Partition: real components vs virtual nodes (workspace roots etc.)
    real = zero & valid_refs
    virtual = zero - valid_refs - ({exclude} if exclude else set())

    # Replace each virtual node with its children (one level only is enough
    # because workspace roots are always shallow)
    for vnode in virtual:
        for child in dependencies.get(vnode, []):
            if child != exclude:
                real.add(child)

    return real


def compute_dependency_depths(
    dependencies: Dict[str, List[str]],
    root_ref: Optional[str],
    valid_refs: Optional[Set[str]] = None,
) -> Dict[str, int]:
    if not dependencies:
        return {}

    dependencies = _prune_cdxgen_flat_deps(dependencies, root_ref)

    # Determine BFS starting points
    if root_ref and dependencies.get(root_ref):
        # Normal case: root has children, BFS from root at depth 0
        start: Dict[str, int] = {root_ref: 0}
    else:
        # Fallback: root is missing or has empty dependsOn.
        # Treat in-degree=0 nodes as depth 1 (virtual direct deps).
        virtual_roots = _indegree_zero_nodes(dependencies, exclude=root_ref, valid_refs=valid_refs)
        if not virtual_roots:
            return {root_ref: 0} if root_ref else {}
        start = {node: 1 for node in virtual_roots}
        if root_ref:
            start[root_ref] = 0

    depths: Dict[str, int] = dict(start)
    queue: deque[Tuple[str, int]] = deque(start.items())

    while queue:
        current, depth = queue.popleft()
        for child in dependencies.get(current, []):
            if child not in depths:
                depths[child] = depth + 1
                queue.append((child, depth + 1))

    return depths


def extract_direct_dependency_refs(
    dependencies: Dict[str, List[str]],
    root_ref: Optional[str],
    valid_refs: Optional[Set[str]] = None,
) -> Set[str]:
    if not dependencies:
        return set()

    if root_ref and root_ref in dependencies:
        dependencies = _prune_cdxgen_flat_deps(dependencies, root_ref)
        direct = set(dependencies.get(root_ref, []) or [])
        if direct:
            return direct
        # Root exists but dependsOn is empty — fall through to in-degree=0

    return _indegree_zero_nodes(dependencies, exclude=root_ref, valid_refs=valid_refs)


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
