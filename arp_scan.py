import csv, sys, socket, ipaddress, psutil, argparse, subprocess, re
from scapy.all import ARP, Ether, srp, IP, TCP, sr1, RandShort, conf
from network_map import generate_network_map

MAC_FILE = "mac.csv"
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


def read_mac_db():
    try:
        with open(MAC_FILE, encoding="utf-8") as f:
            return {r[0].strip().upper(): r[1].strip() for r in csv.reader(f, delimiter=";") if len(r) >= 2}
    except FileNotFoundError:
        return {}

def find_vendor(mac, mac_db):
    return mac_db.get(mac.upper().replace(":", "").replace("-", "")[:6], "Unknown")

def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

def detect_network(local_ip):
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{addr.netmask}").prefixlen
                return ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
    raise RuntimeError("Impossible de détecter le réseau local")

def get_gateway(local_ip):
    # Tentative Windows (ipconfig)
    try:
        output = subprocess.check_output("ipconfig", text=True, encoding="utf-8", errors="ignore")
        for block in output.split("\n\n"):
            if local_ip in block:
                m = re.search(r"(?:Passerelle par défaut|Default Gateway)[ .:]*([\d.]+)", block)
                if m:
                    return m.group(1)
    except Exception:
        pass

    # Fallback : lire la table de routage via Scapy
    try:
        from scapy.all import conf
        gw = conf.route.route("0.0.0.0")[2]  # (iface, src_ip, gateway)
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass

    return None

def get_iface(local_ip):
    for iface in conf.ifaces.values():
        if getattr(iface, "ip", None) == local_ip:
            return iface.name
    return None

def syn_scan(ip, port, timeout=0.2):
    pkt = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=False)
    if resp and resp.haslayer(TCP):
        return {0x12: "open", 0x14: "closed"}.get(resp[TCP].flags, "filtered")
    return "filtered"

def arp_scan(net, iface, local_ip=None):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=2, retry=1, verbose=False, **{"iface": iface} if iface else {})
    seen = {local_ip} if local_ip else set()  # exclut d'emblée le scanner lui-même
    hosts = []
    for _, r in answered:
        if r.psrc not in seen:
            hosts.append((r.psrc, r.hwsrc))
            seen.add(r.psrc)
    return hosts

def main():
    parser = argparse.ArgumentParser(description="ARP Network Scanner")
    parser.add_argument("network", nargs="?", help="Réseau à scanner, ex: 192.168.1.0/24")
    parser.add_argument("--map", action="store_true", help="Génère une carte réseau PNG")
    args = parser.parse_args()

    local_ip = get_local_ip()
    net = ipaddress.ip_network(args.network, strict=False) if args.network else detect_network(local_ip)
    gateway_ip = get_gateway(local_ip)
    iface = get_iface(local_ip)
    mac_db = read_mac_db()

    print(f"IP locale : {local_ip}\nRéseau détecté : {net}\nGateway détectée : {gateway_ip}\nInterface Scapy : {iface}")
    print("Scan ARP en cours...")

    try:
        hosts = arp_scan(net, iface, local_ip=local_ip)  # ✅ un seul appel, avec filtre
    except Exception as e:
        print(f"Erreur pendant le scan ARP : {e}")
        sys.exit()

    total = len(hosts)
    print(f"[+] {total} hôtes détectés\n")

    scan_results = []
    with open("scan_result.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["ip", "mac", "company", "ports_str"])

        for i, (ip, mac) in enumerate(hosts, 1):
            print(f"[{i}/{total}] Scan de {ip} ...", end="\r")
            company = find_vendor(mac, mac_db)
            open_ports = [p for p in COMMON_PORTS if syn_scan(ip, p) == "open"]
            writer.writerow([ip, mac, company, ",".join(map(str, open_ports))])
            scan_results.append({"ip": ip, "mac": mac, "company": company, "ports": open_ports})

    print("\nScan terminé. Résultats enregistrés dans scan_result.csv")

    if args.map:
        generate_network_map(scan_results, local_ip, net, gateway_ip)

if __name__ == "__main__":
    main()