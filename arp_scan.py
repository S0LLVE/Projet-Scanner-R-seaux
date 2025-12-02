import csv
import sys
import socket
import ipaddress
import psutil
from scapy.all import ARP, Ether, srp, IP, TCP, sr1, RandShort, show_interfaces

MAC_FILE = "mac.csv"

def readCsvMac():
    mac_db = {}

    try:
        with open(MAC_FILE, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file, delimiter=';')
            for row in reader:
                oui = row[0].strip().upper()
                vendor = row[1].strip()
                mac_db[oui] = vendor
                    
        return mac_db
    except FileNotFoundError:
        print(f"fichier CSV non trouvé")
        return {}

def find_vendor(mac, mac_db):
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return mac_db.get(oui, "Unknown")

def get_local_ip():
    # AF_INET -> IPV4
    # SOCK_DGRAM -> UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        print("no ip")
        sys.exit()
    finally:
        s.close()
    return ip

def detect_network():
    local_ip = get_local_ip()

    # parcourt toutes les interfaces réseau
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                netmask = addr.netmask  # 255.255.252.0
                if not netmask:
                    continue

                # convertit le netmask en  /22, /24 ...
                prefix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen

                # construire le réseau complet
                return ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)

def syn_scan(ip, port, timeout=0.1):
    src_port = RandShort()
    syn_packet = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")

    response = sr1(syn_packet, timeout=timeout, verbose=False)

    if response is None:
        return "filtered"

    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:     # SYN/ACK = port ouvert
            return "open"
        elif flags == 0x14:   # RST = port fermé
            return "closed"

    return "filtered"

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143,
    443, 445, 3306, 3389, 8080
]

def main():    
    if len(sys.argv) < 2:
        try:
            net = detect_network()
        except Exception as e:
            sys.exit()
    else:
        net = ipaddress.ip_network(sys.argv[1], strict=False)

    mac_db = readCsvMac()
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=str(net))
    packet = ether / arp


    print("Scan ARP en cours...")
    answered, _ = srp(packet, timeout=1, retry=0, verbose=False)

    hosts = []
    for send, recv in answered:
        hosts.append((recv.psrc, recv.hwsrc))

    total = len(hosts)
    print(f"[+] {total} hôtes détectés\n")


    with open("scan_result.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(["ip", "mac", "company", "ports_str"])

        count = 1
        for ip, mac in hosts:
            print(f"[{count}/{total}] Scan de {ip} ...", end="\r")

            company = find_vendor(mac, mac_db)

            open_ports = []
            for port in COMMON_PORTS:
                state = syn_scan(ip, port)
                if state == "open":
                    open_ports.append(str(port))

            ports_str = ",".join(open_ports)
            writer.writerow([ip, mac, company, ports_str])

            count += 1

    print("\n\nScan terminé. Résultats enregistrés dans scan_result.csv")
 

main()