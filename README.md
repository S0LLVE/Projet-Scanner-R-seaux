# 🖧 ARP Network Scanner

## 📌 Présentation

Ce projet est un **outil de découverte réseau** permettant d’identifier les machines actives sur un réseau local à l’aide du protocole **ARP (Address Resolution Protocol)**.

Le programme détecte automatiquement la configuration réseau de la machine hôte, puis scanne l’ensemble du réseau local afin de recenser les **adresses IP actives**, les **adresses MAC associées**, ainsi que des informations complémentaires utiles à l’analyse réseau.

---

## ⚙️ Fonctionnalités

L’outil permet de :

- Détecter automatiquement :
  - l’adresse IP locale
  - le masque réseau
- Construire dynamiquement le réseau à scanner
- Effectuer un **scan ARP par broadcast**
- Identifier les hôtes actifs sur le réseau
- Associer chaque adresse MAC à son **constructeur**
- Réaliser un **scan SYN** sur une liste de ports courants
- Exporter les résultats dans un fichier **CSV**

---

## 📋 Résultats

Chaque hôte découvert est enregistré avec les informations suivantes :

- Adresse IP
- Adresse MAC
- Fabricant de la carte réseau
- Ports ouverts détectés

### Exemple de sortie :

IP MAC Vendor Ports ouverts
10.69.0.12 9c:67:d6:68:e1:a5 Intel Corp 22,80
10.69.1.48 7c:5a:1c:cc:61:bd Apple Inc 443
10.69.2.15 84:b8:02:aa:11:03 Unknown 

- Les résultats complets sont sauvegardés dans le fichier :

scan_result.csv

---

## 🔐 Contexte d’utilisation

Cet outil peut être utilisé pour :

- la **cartographie rapide d’un réseau local**
- la détection de machines inconnues
- un **pré-audit de sécurité**

---

## 🧰 Prérequis

- **Python 3.9+**
- Droits administrateur requis
- Système compatible avec **Scapy**

---

## ⚙️ Installation

### 1. Installer Python

Télécharger la dernière version stable de Python :  
https://www.python.org/downloads/

---

### 2. Installer Npcap (Windows uniquement)

Télécharger et installer Npcap :  
https://npcap.com/#download

Lors de l’installation, cocher :
- **Install Npcap in WinPcap API-compatible Mode**

---

### 3. Installer les dépendances Python

```bash
pip install scapy psutil
```

### 4. Utilisation

Lancer le script :

```bash
python arp_scan.py
```

Scanner un réseau spécifique :

```bash
python arp_scan.py 192.168.1.0/24
```