"""Deterministic module dependency graph construction and cycle detection."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from app.analyzers.architecture.models import DependencyCycle, ModuleNode


class DependencyGraph:
    """Directed, statically constructed module dependency graph."""

    def __init__(self, modules: dict[str, ModuleNode]) -> None:
        self.modules = modules  # module_name -> ModuleNode
        self.adj_list: dict[str, set[str]] = defaultdict(set)
        self.rev_adj_list: dict[str, set[str]] = defaultdict(set)
        self._build_graph()

    def _build_graph(self) -> None:
        """Construct deterministic adjacency lists from local module dependencies."""
        for mod_name in sorted(self.modules.keys()):
            mod = self.modules[mod_name]
            for target in sorted(mod.local_dependencies):
                if target in self.modules and target != mod_name:
                    self.adj_list[mod_name].add(target)
                    self.rev_adj_list[target].add(mod_name)

    def get_dependencies(self, module_name: str) -> list[str]:
        """Return direct dependencies of a module in deterministic sorted order."""
        return sorted(self.adj_list.get(module_name, set()))

    def get_dependents(self, module_name: str) -> list[str]:
        """Return modules that directly depend on module_name in sorted order."""
        return sorted(self.rev_adj_list.get(module_name, set()))

    def in_degree(self, module_name: str) -> int:
        """Return fan-in (number of incoming dependency edges)."""
        return len(self.rev_adj_list.get(module_name, set()))

    def out_degree(self, module_name: str) -> int:
        """Return fan-out (number of outgoing dependency edges)."""
        return len(self.adj_list.get(module_name, set()))

    def find_cycles(self) -> list[DependencyCycle]:
        """Detect all simple directed cycles deterministically.

        Uses depth-first search cycle enumeration with canonical rotation normalization
        to guarantee stable ordering and prevent duplicate cycles.
        """
        all_cycles: list[DependencyCycle] = []
        seen_cycle_ids: set[str] = set()

        nodes = sorted(self.modules.keys())

        # Tarjan's SCC to isolate components that contain cycles
        sccs = self._tarjan_scc(nodes)
        for scc in sccs:
            if len(scc) < 2:
                # Single node with no self-loop is not a cycle
                node = scc[0]
                if node in self.adj_list.get(node, set()):
                    canonical = [node, node]
                    c_id = hashlib.sha256("->".join(canonical).encode("utf-8")).hexdigest()[:16]
                    if c_id not in seen_cycle_ids:
                        seen_cycle_ids.add(c_id)
                        all_cycles.append(DependencyCycle(cycle_path=canonical, length=1, cycle_id=c_id))
                continue

            # In each SCC, find elementary cycles using deterministic DFS
            scc_set = set(scc)
            for start_node in sorted(scc):
                visited = [start_node]
                self._dfs_cycles(start_node, start_node, scc_set, visited, all_cycles, seen_cycle_ids)

        # Sort cycles deterministically by length, then canonical string
        all_cycles.sort(key=lambda c: (c.length, c.canonical_repr))
        return all_cycles

    def _dfs_cycles(
        self,
        current: str,
        start_node: str,
        scc_set: set[str],
        path: list[str],
        all_cycles: list[DependencyCycle],
        seen_cycle_ids: set[str],
        max_depth: int = 15,
    ) -> None:
        """DFS recursive traversal to discover cycles returning to start_node."""
        if len(path) > max_depth:
            return

        for neighbor in sorted(self.adj_list.get(current, set())):
            if neighbor not in scc_set:
                continue

            if neighbor == start_node and len(path) >= 2:
                # Closed a cycle back to start_node
                canonical = self._canonicalize_cycle(path + [start_node])
                c_id = hashlib.sha256("->".join(canonical).encode("utf-8")).hexdigest()[:16]
                if c_id not in seen_cycle_ids:
                    seen_cycle_ids.add(c_id)
                    all_cycles.append(
                        DependencyCycle(
                            cycle_path=canonical,
                            length=len(canonical) - 1,
                            cycle_id=c_id,
                        )
                    )
            elif neighbor not in path:
                # Continue searching along unvisited path
                path.append(neighbor)
                self._dfs_cycles(neighbor, start_node, scc_set, path, all_cycles, seen_cycle_ids, max_depth)
                path.pop()

    @staticmethod
    def _canonicalize_cycle(cycle: list[str]) -> list[str]:
        """Normalize a cycle path to start at the lexicographically smallest node.

        For example, [B, C, A, B] becomes [A, B, C, A].
        """
        nodes = cycle[:-1]
        if not nodes:
            return cycle

        min_idx = 0
        min_val = nodes[0]
        for i, node in enumerate(nodes):
            if node < min_val:
                min_val = node
                min_idx = i

        rotated = nodes[min_idx:] + nodes[:min_idx]
        return rotated + [rotated[0]]

    def _tarjan_scc(self, nodes: list[str]) -> list[list[str]]:
        """Tarjan's algorithm for strongly connected components, deterministically ordered."""
        index = 0
        indices: dict[str, int] = {}
        lowlinks: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        sccs: list[list[str]] = []

        def strongconnect(v: str) -> None:
            nonlocal index
            indices[v] = index
            lowlinks[v] = index
            index += 1
            stack.append(v)
            on_stack.add(v)

            for w in sorted(self.adj_list.get(v, set())):
                if w not in indices:
                    strongconnect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif w in on_stack:
                    lowlinks[v] = min(lowlinks[v], indices[w])

            if lowlinks[v] == indices[v]:
                scc: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    scc.append(w)
                    if w == v:
                        break
                scc.sort()
                sccs.append(scc)

        for node in sorted(nodes):
            if node not in indices:
                strongconnect(node)

        # Sort SCCs deterministically by first node
        sccs.sort(key=lambda s: s[0] if s else "")
        return sccs
