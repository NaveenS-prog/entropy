"""Clustering and candidate reduction engine for Code Duplication detection.

Implements:
- Size-bucket indexing to avoid O(n^2) comparisons.
- Exclusion filters for trivial snippets, getters, and test fixtures.
- Deterministic clustering of pairwise matches into connected components.
- Detection of repeated boilerplate patterns across multiple functions.
"""

from __future__ import annotations

import difflib
import hashlib
from collections import defaultdict

from app.analyzers.duplication.models import (
    BoilerplatePattern,
    DuplicationCluster,
    FunctionSignature,
)

# Minimum thresholds for meaningful structural duplication
MIN_STATEMENTS = 2
MIN_AST_NODES = 10
SIMILARITY_THRESHOLD = 0.85

# Directories and file patterns excluded from false-positive reporting
EXCLUDED_PATH_SUBSTRINGS = (
    "/tests/",
    "tests/",
    "/test/",
    "test_",
    "_test.py",
    "fixtures/",
    "/fixtures/",
    "conftest.py",
    "migrations/",
    "site-packages",
    ".venv",
)


def is_excluded_path(file_path: str) -> bool:
    """Return True if the file path belongs to tests, fixtures, or generated code."""
    path_lower = file_path.lower().replace("\\", "/")
    return any(p in path_lower for p in EXCLUDED_PATH_SUBSTRINGS)


def is_trivial_function(sig: FunctionSignature) -> bool:
    """Filter out trivial snippets, empty functions, or simple getters/setters."""
    if sig.statement_count < MIN_STATEMENTS or sig.node_count < MIN_AST_NODES:
        return True

    # Single pass or return self._x
    if sig.statement_count == 1:
        return True

    # Simple constructor initializing 1-2 attributes
    if sig.name == "__init__" and sig.statement_count <= 2:
        return True

    return False


class DuplicationDetector:
    """Coordinates deterministic candidate indexing, similarity matching, and clustering."""

    def __init__(
        self,
        min_statements: int = MIN_STATEMENTS,
        min_nodes: int = MIN_AST_NODES,
        similarity_threshold: float = SIMILARITY_THRESHOLD,
    ) -> None:
        self.min_statements = min_statements
        self.min_nodes = min_nodes
        self.similarity_threshold = similarity_threshold

    def find_duplications(
        self, signatures: list[FunctionSignature]
    ) -> tuple[list[DuplicationCluster], list[BoilerplatePattern]]:
        """Identify exact structural duplicates, similar functions, and boilerplate patterns."""
        # 1. Filter out excluded paths and trivial functions
        eligible: list[FunctionSignature] = [
            s for s in signatures if not is_excluded_path(s.file_path) and not is_trivial_function(s)
        ]

        if len(eligible) < 2:
            return [], []

        # 2. Level 1: Exact Hash Grouping (O(N))
        exact_buckets: dict[str, list[FunctionSignature]] = defaultdict(list)
        for sig in eligible:
            exact_buckets[sig.exact_hash].append(sig)

        # Track which pairs are already matched to avoid duplicate work
        adjacency: dict[str, set[str]] = defaultdict(set)
        sig_lookup: dict[str, FunctionSignature] = {s.id: s for s in eligible}
        pair_similarity: dict[tuple[str, str], float] = {}

        # Add exact matches to graph
        for bucket in exact_buckets.values():
            if len(bucket) >= 2:
                for i in range(len(bucket)):
                    for j in range(i + 1, len(bucket)):
                        u, v = bucket[i].id, bucket[j].id
                        adjacency[u].add(v)
                        adjacency[v].add(u)
                        pair_similarity[(min(u, v), max(u, v))] = 1.0

        # 3. Level 2: Similar Functions across size-based candidate buckets
        # Group by node-count bucket to prune distant candidates
        size_buckets: dict[int, list[FunctionSignature]] = defaultdict(list)
        for sig in eligible:
            bucket_idx = sig.node_count // 6
            size_buckets[bucket_idx].append(sig)

        checked_pairs: set[tuple[str, str]] = set()

        for bucket_idx, bucket_members in size_buckets.items():
            # Check within bucket and adjacent bucket
            candidates = bucket_members + size_buckets.get(bucket_idx + 1, [])
            for i in range(len(candidates)):
                for j in range(i + 1, len(candidates)):
                    sig_a = candidates[i]
                    sig_b = candidates[j]
                    if sig_a.id == sig_b.id:
                        continue

                    pair_key = (min(sig_a.id, sig_b.id), max(sig_a.id, sig_b.id))
                    if pair_key in checked_pairs or pair_key in pair_similarity:
                        continue
                    checked_pairs.add(pair_key)

                    # Quick structural heuristic: parameter count and statement count must be reasonably close
                    if abs(sig_a.statement_count - sig_b.statement_count) > 3:
                        continue
                    if abs(sig_a.parameter_count - sig_b.parameter_count) > 2:
                        continue

                    # Node count disparity check
                    max_nodes = max(sig_a.node_count, sig_b.node_count)
                    if max_nodes > 0 and abs(sig_a.node_count - sig_b.node_count) / max_nodes > 0.35:
                        continue

                    # Material difference check: if both have operators, they cannot be completely disjoint
                    if sig_a.operators and sig_b.operators:
                        if not (set(sig_a.operators) & set(sig_b.operators)):
                            continue

                    # Compute deterministic sequence similarity
                    matcher = difflib.SequenceMatcher(
                        None, sig_a.structural_tokens, sig_b.structural_tokens
                    )
                    ratio = matcher.ratio()

                    if ratio >= self.similarity_threshold:
                        adjacency[sig_a.id].add(sig_b.id)
                        adjacency[sig_b.id].add(sig_a.id)
                        pair_similarity[pair_key] = ratio

        # 4. Form connected components (clusters)
        clusters: list[DuplicationCluster] = []
        visited: set[str] = set()

        # Sort keys deterministically by file, line, name
        sorted_sig_ids = sorted(
            adjacency.keys(),
            key=lambda sid: (
                sig_lookup[sid].file_path,
                sig_lookup[sid].location.line_start,
                sig_lookup[sid].name,
            ),
        )

        for sid in sorted_sig_ids:
            if sid in visited:
                continue

            # BFS to gather connected component
            component_ids: list[str] = []
            queue = [sid]
            visited.add(sid)

            while queue:
                curr = queue.pop(0)
                component_ids.append(curr)
                for neighbor in sorted(adjacency[curr]):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            if len(component_ids) < 2:
                continue

            # Sort members deterministically
            members = [sig_lookup[cid] for cid in component_ids]
            members.sort(key=lambda m: (m.file_path, m.location.line_start, m.name))
            representative = members[0]

            # Compute average similarity in cluster
            similarities: list[float] = []
            is_exact = True
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    pk = (min(members[i].id, members[j].id), max(members[i].id, members[j].id))
                    sim = pair_similarity.get(pk, 1.0)
                    similarities.append(sim)
                    if sim < 0.999:
                        is_exact = False

            avg_sim = sum(similarities) / len(similarities) if similarities else 1.0
            files = {m.file_path for m in members}
            is_cross_file = len(files) > 1

            cluster_seed = f"{representative.exact_hash}:{','.join(m.id for m in members)}"
            cluster_id = hashlib.sha256(cluster_seed.encode("utf-8")).hexdigest()[:16]

            clusters.append(
                DuplicationCluster(
                    cluster_id=cluster_id,
                    representative=representative,
                    members=members,
                    similarity=round(avg_sim, 2),
                    is_exact=is_exact,
                    is_cross_file=is_cross_file,
                    normalized_size=representative.node_count,
                    files=files,
                )
            )

        # 5. Level 3: Repeated Boilerplate Detection
        boilerplate_patterns = self._detect_boilerplate_patterns(eligible, clusters)

        # Sort clusters deterministically by representative location
        clusters.sort(
            key=lambda c: (
                c.representative.file_path,
                c.representative.location.line_start,
                c.representative.name,
            )
        )

        return clusters, boilerplate_patterns

    def _detect_boilerplate_patterns(
        self,
        signatures: list[FunctionSignature],
        existing_clusters: list[DuplicationCluster],
    ) -> list[BoilerplatePattern]:
        """Detect repeated structural boilerplate wrappers (e.g. repeated try-catch fallback blocks)."""
        clustered_ids = {m.id for c in existing_clusters for m in c.members}
        boilerplate_buckets: dict[str, list[FunctionSignature]] = defaultdict(list)

        for sig in signatures:
            # Look for functions characterized primarily by control flow shapes like try-except or check-return
            cf_shape = sig.control_flow_shape
            if len(cf_shape) >= 2 and any("except" in cf for cf in cf_shape):
                shape_key = f"try_catch:{':'.join(cf_shape)}"
                boilerplate_buckets[shape_key].append(sig)

        patterns: list[BoilerplatePattern] = []
        for shape_key, funcs in boilerplate_buckets.items():
            # If >= 3 functions share this exact boilerplate shape across >= 2 files
            files = {f.file_path for f in funcs}
            if len(funcs) >= 3 and len(files) >= 2:
                # Filter out functions that are already fully captured in exact clusters
                non_clustered = [f for f in funcs if f.id not in clustered_ids]
                if len(non_clustered) >= 3:
                    non_clustered.sort(key=lambda f: (f.file_path, f.location.line_start))
                    rep = non_clustered[0]
                    pattern_id = hashlib.sha256(
                        f"boilerplate:{shape_key}:{','.join(f.id for f in non_clustered)}".encode()
                    ).hexdigest()[:16]

                    patterns.append(
                        BoilerplatePattern(
                            pattern_id=pattern_id,
                            pattern_type="repeated_exception_wrapper",
                            representative=rep,
                            occurrences=[(f, f.location) for f in non_clustered],
                            frequency=len(non_clustered),
                            files={f.file_path for f in non_clustered},
                        )
                    )

        return patterns
