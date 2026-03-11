import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

NODE_COLORS = {"local": "#4A90D9", "gateway": "#E8A838", "host": "#5CB85C"}
NODE_SIZES  = {"local": 3500, "gateway": 2800, "host": 2400}

def generate_network_map(scan_results, local_ip, net, gateway_ip=None, output_file="network_map.png"):
    G = nx.Graph()

    local_node = f"Scanner\n{local_ip}"
    G.add_node(local_node, node_type="local")

    # Gateway node (optionnel)
    gateway_node = None
    if gateway_ip:
        gateway_node = f"Gateway\n{gateway_ip}"
        G.add_node(gateway_node, node_type="gateway")
        G.add_edge(local_node, gateway_node)

    parent = gateway_node if gateway_node else local_node

    # Ajout des hôtes — TOUS, même sans gateway
    for h in scan_results:
        if gateway_ip and h["ip"] == gateway_ip:
            continue
        ports_str = ", ".join(map(str, h["ports"])) if h["ports"] else "Aucun port ouvert"
        label = f"{h['ip']}\n{h['company']}\n[{ports_str}]"
        G.add_node(label, node_type="host")
        G.add_edge(parent, label)

    if G.number_of_nodes() == 0:
        print("Aucun hôte à afficher.")
        return

    fig, ax = plt.subplots(figsize=(18, 11))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#1a1a2e")

    # Layout adaptatif selon le nombre de nœuds
    k = max(1.2, 2.5 / max(len(scan_results), 1))
    pos = nx.spring_layout(G, seed=42, k=k, iterations=100)

    # Dessin des arêtes
    nx.draw_networkx_edges(G, pos, ax=ax, width=1.8, alpha=0.4, edge_color="#aaaaaa", style="dashed")

    # Dessin des nœuds par type
    for ntype in ("local", "gateway", "host"):
        nodes = [n for n, a in G.nodes(data=True) if a.get("node_type") == ntype]
        if nodes:
            nx.draw_networkx_nodes(
                G, pos, ax=ax,
                nodelist=nodes,
                node_color=NODE_COLORS[ntype],
                node_size=NODE_SIZES[ntype],
                alpha=0.92,
                linewidths=2,
                edgecolors="white"
            )

    # Labels
    nx.draw_networkx_labels(G, pos, ax=ax, font_size=7.5, font_color="white", font_weight="bold")

    # Légende
    legend = [mpatches.Patch(facecolor=c, edgecolor="white", label=k.capitalize())
              for k, c in NODE_COLORS.items()]
    ax.legend(handles=legend, loc="upper left", fontsize=10,
              facecolor="#2a2a4a", edgecolor="white", labelcolor="white")

    # Stats dans un encadré
    stats = f"Hôtes détectés : {len(scan_results)}  |  Réseau : {net}"
    ax.text(0.5, 0.02, stats, transform=ax.transAxes,
            fontsize=9, color="#aaaaaa", ha="center",
            bbox=dict(boxstyle="round,pad=0.4", facecolor="#2a2a4a", edgecolor="#555"))

    ax.set_title(f"Network Map — {net}", fontsize=15, fontweight="bold",
                 color="white", pad=15)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"Carte réseau générée : {output_file}")