import sys
import socket
import ipaddress
import psutil # type: ignore
from scapy.all import ARP, Ether, srp, conf # type: ignore


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


def main():
    try:
        net = detect_network()
    except Exception as e:
        print("[!] Erreur détection réseau :", e)
        print("[!] Fallback en 192.168.1.0/24")
        sys.exit()

    print(f"[+] ARP scan sur {net} (interface par défaut: {conf.iface})")

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=str(net))
    packet = ether / arp

    # envoi / réception
    answered, _ = srp(packet, timeout=2, retry=1, verbose=False)

    results = []
    for send, recv in answered:
        ip = recv.psrc
        mac = recv.hwsrc
        results.append((ip, mac))

    if not results:
        print("Aucun hôte trouvé (check ton interface / firewall).")
        return

    print(f"\nHôtes trouvés ({len(results)}):")
    print("IP\t\tMAC")
    for ip, mac in sorted(results, key=lambda x: list(map(int, x[0].split(".")))):
        print(f"{ip}\t{mac}")


main()
