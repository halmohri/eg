from pathlib import Path
import json
import networkx as nx


class ConfigGraph:
    """
    Wrapper around a directed graph of configurations/relationships.
    Uses networkx DiGraph.
    """

    class Node:
        def __init__(self, node_id: str, label: str | None = None, data: dict | None = None):
            self.id = node_id
            self.label = label or node_id
            self.data = data or {}

    def __init__(self):
        self.graph = nx.DiGraph()

    def load_from_json(self, path: Path | str):
        data = json.loads(Path(path).read_text())
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        for n in nodes:
            self.graph.add_node(n.get("id"), **{k: v for k, v in n.items() if k != "id"})
        for e in edges:
            self.graph.add_edge(e.get("source"), e.get("target"), **{k: v for k, v in e.items() if k not in {"source", "target"}})
        return self.graph

    def load_nodes(self, path: Path | str):
        data = json.loads(Path(path).read_text())
        nodes = data.get("nodes", [])
        for n in nodes:
            node_id = n.get("id")
            node = self.Node(node_id=node_id, label=n.get("label"), data={k: v for k, v in n.items() if k not in {"id", "label"}})
            self.graph.add_node(node_id, label=node.label, node_obj=node, **node.data)
        return {n: self.graph.nodes[n].get("node_obj") for n in self.graph.nodes}

    def get_node(self, node_id: str):
        return self.graph.nodes[node_id].get("node_obj")

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))
