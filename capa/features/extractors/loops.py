from networkx.algorithms.components import strongly_connected_components
from networkx import nx


def has_loop(edges, threshold=2):
    """ check if a list of edges representing a directed graph contains a loop

        args:
            edges: list of edge sets representing a directed graph i.e. [(1, 2), (2, 1)]
            threshold: min number of nodes contained in loop

        returns:
            bool
    """
    g = nx.DiGraph()
    g.add_edges_from(edges)
    return any(len(comp) >= threshold for comp in strongly_connected_components(g))
