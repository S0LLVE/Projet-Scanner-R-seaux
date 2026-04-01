import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import networkx as nx

NODE_COLORS = {"local": "#4A90D9", "gateway": "#E8A838", "host": "#5CB85C"}
NODE_SIZES = {"local": 3500, "gateway": 2800, "host": 2400}


def generate_network_map(scan_results, local_ip, net, gateway_ip=None, output_file="network_map.png"):
    if not scan_results:
        print("Aucun hote a afficher.")
        return

    graph = nx.Graph()

    local_node = f"Scanner\n{local_ip}"
    graph.add_node(local_node, node_type="local")

    gateway_node = None
    if gateway_ip:
        gateway_node = f"Gateway\n{gateway_ip}"
        graph.add_node(gateway_node, node_type="gateway")
        graph.add_edge(local_node, gateway_node)

    parent = gateway_node if gateway_node else local_node

    for host in scan_results:
        if gateway_ip and host["ip"] == gateway_ip:
            continue
        ports = host.get("ports", [])
        ports_str = ", ".join(map(str, ports)) if ports else "Aucun port ouvert"
        label = f"{host['ip']}\n{host['company']}\n[{ports_str}]"
        graph.add_node(label, node_type="host")
        graph.add_edge(parent, label)

    fig, ax = plt.subplots(figsize=(18, 11))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#1a1a2e")

    k_value = max(1.2, 2.5 / max(len(scan_results), 1))
    positions = nx.spring_layout(graph, seed=42, k=k_value, iterations=100)

    nx.draw_networkx_edges(
        graph,
        positions,
        ax=ax,
        width=1.8,
        alpha=0.4,
        edge_color="#aaaaaa",
        style="dashed",
    )

    for node_type in ("local", "gateway", "host"):
        nodes = [node for node, attrs in graph.nodes(data=True) if attrs.get("node_type") == node_type]
        if nodes:
            nx.draw_networkx_nodes(
                graph,
                positions,
                ax=ax,
                nodelist=nodes,
                node_color=NODE_COLORS[node_type],
                node_size=NODE_SIZES[node_type],
                alpha=0.92,
                linewidths=2,
                edgecolors="white",
            )

    nx.draw_networkx_labels(graph, positions, ax=ax, font_size=7.5, font_color="white", font_weight="bold")

    legend = [
        mpatches.Patch(facecolor=color, edgecolor="white", label=node_type.capitalize())
        for node_type, color in NODE_COLORS.items()
    ]
    ax.legend(
        handles=legend,
        loc="upper left",
        fontsize=10,
        facecolor="#2a2a4a",
        edgecolor="white",
        labelcolor="white",
    )

    stats = f"Hotes detectes : {len(scan_results)}  |  Reseau : {net}"
    ax.text(
        0.5,
        0.02,
        stats,
        transform=ax.transAxes,
        fontsize=9,
        color="#aaaaaa",
        ha="center",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#2a2a4a", edgecolor="#555"),
    )

    ax.set_title(f"Network Map - {net}", fontsize=15, fontweight="bold", color="white", pad=15)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"Carte reseau generee : {output_file}")
