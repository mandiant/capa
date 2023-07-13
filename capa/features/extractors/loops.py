# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import networkx
from networkx.algorithms.components import strongly_connected_components


def has_loop(edges, threshold=2):
    """check if a list of edges representing a directed graph contains a loop

    args:
        edges: list of edge sets representing a directed graph i.e. [(1, 2), (2, 1)]
        threshold: min number of nodes contained in loop

    returns:
        bool
    """
    g = networkx.DiGraph()
    g.add_edges_from(edges)
    return any(len(comp) >= threshold for comp in strongly_connected_components(g))
