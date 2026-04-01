# 🖧 ARP Network Scanner

## 📌 Présentation

Ce projet est un **outil de découverte réseau** permettant d'identifier les machines actives sur un réseau local à l'aide du protocole **ARP (Address Resolution Protocol)**.

Le programme détecte automatiquement la configuration réseau de la machine hôte, scanne le réseau local, recense les **adresses IP actives**, les **adresses MAC associées**, effectue un **scan SYN** sur les ports courants, et peut générer une **carte réseau visuelle** au format PNG.

---

## ⚙️ Fonctionnalités

- Détection automatique de l'IP locale, du masque réseau et de la gateway
- Scan ARP par broadcast sur le réseau local
- Exclusion automatique du scanner lui-même des résultats
- Identification du fabricant via l'OUI de l'adresse MAC (`mac.csv`)
- Scan SYN sur une liste de ports courants
- Export des résultats dans un fichier **CSV**
- Génération d'une **carte réseau PNG** avec `--map`

---

## 🔌 Ports scannés

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 139 | NetBIOS |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |
| 8080 | HTTP Alt |

---

## 📋 Résultats

Chaque hôte découvert est enregistré avec :

- Adresse IP
- Adresse MAC
- Fabricant de la carte réseau
- Ports ouverts détectés

Les résultats sont sauvegardés dans `scan_result.csv` (séparateur `;`) :
```
ip;mac;company;ports_str
10.174.153.155;9c:67:d6:68:e1:a5;Intel Corp;22,80
10.174.153.241;7c:5a:1c:cc:61:bd;Apple Inc;443,445
```

---

## 🗺️ Carte réseau

Avec le flag `--map`, une carte réseau PNG est générée (`network_map.png`) représentant :

- 🔵 **Scanner** — la machine locale
- 🟡 **Gateway** — la passerelle (si détectée)
- 🟢 **Hosts** — les hôtes découverts avec leurs ports ouverts

---

## 🔐 Contexte d'utilisation

- Cartographie rapide d'un réseau local
- Détection de machines inconnues
- Pré-audit de sécurité

> ⚠️ À utiliser uniquement sur des réseaux dont vous êtes propriétaire ou pour lesquels vous avez une autorisation explicite.

---

## 🧰 Prérequis

- **Python 3.9+**
- **Droits administrateur** (requis pour les scans ARP et SYN)

---

## ⚙️ Installation

### 1. Installer Python

https://www.python.org/downloads/

---

### 2. Installer Npcap (Windows uniquement)

https://npcap.com/#download

> Cocher **"Install Npcap in WinPcap API-compatible Mode"** lors de l'installation.

---

### 3. Installer les dépendances Python
```bash
pip install -r requirements.txt
```

| Package | Rôle |
|---------|------|
| `scapy` | Scan ARP et SYN |
| `psutil` | Détection des interfaces réseau |
| `networkx` | Génération du graphe réseau |
| `matplotlib` | Rendu de la carte PNG |

---

## 🚀 Utilisation

Scanner le réseau local détecté automatiquement :
```bash
python arp_scan.py
```

Scanner un réseau spécifique :
```bash
python arp_scan.py 192.168.1.0/24
```

Scanner et générer la carte réseau PNG :
```bash
python arp_scan.py --map
python arp_scan.py 192.168.1.0/24 --map
```