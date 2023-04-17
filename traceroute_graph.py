'''
Created on April 16, 2023
@author: Thierry Ung, Jack Thay
Graphical side of ROUT Project
'''
import subprocess
import re
import networkx as nx
import matplotlib.pyplot as plt

# Main function
def traceroute(destination):
    tracert = subprocess.Popen(["traceroute", destination], stdout=subprocess.PIPE)
    output = tracert.communicate()[0].decode("utf-8")
    return output

# Creating list from output
def parse_traceroute(output):
    lines = output.split("\n")
    hops = []
    for line in lines:
        match = re.match("^(\d+) (.*)", line)
        if match:
            hop = match.group(1)
            addresses = match.group(2).split("  ")
            hops.append((hop, addresses))
    return hops

# Building graph from hops obtained
def build_graph(hops):
    graph = nx.DiGraph()
    for hop in hops:
        graph.add_node(hop[0], addresses=hop[1])
        if len(hop[1]) > 1:
            for i in range(1, len(hop[1])):
                graph.add_edge(hop[0], str(int(hop[0]) + 1), weight=i, label=hop[1][i])
    return graph

# Drawing graph from data
def draw_graph(graph): 
    pos = nx.spring_layout(graph)
    labels = {node: node for node in graph.nodes()}
    nx.draw(graph, pos, with_labels=True, node_color="lightblue", labels=labels)
    edge_labels = nx.get_edge_attributes(graph, "label")
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels)
    plt.show()

# Saving graph into a png file
def save_graph(graph): 
    plt.figure(figsize=(10, 10))
    draw_graph(graph)
    plt.savefig("traceroute_graph.png")

if __name__ == "__main__":
    destination = input("Enter the destination host or IP address: ")
    output = traceroute(destination)
    hops = parse_traceroute(output)
    graph = build_graph(hops)
    draw_graph(graph)
    save_graph(graph)


