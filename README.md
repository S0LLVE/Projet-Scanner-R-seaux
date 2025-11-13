## Présentation

Ce programme effectue un **scan ARP** sur le réseau local afin d’identifier :

- les adresses **IP** actives  
- les adresses **MAC** associées  

Le scanner :  
- détecte **automatiquement ton IP locale**,  
- récupère **automatiquement le masque réseau**,  
- scanne l’ensemble du réseau via **ARP broadcast**,  
- affiche les hôtes trouvés.

### 📋 Résultats lisibles
Chaque hôte découvert s'affiche sous la forme :

IP MAC
10.69.0.12 9c:67:d6:68:e1:a5
10.69.1.48 7c:5a:1c:cc:61:bd
10.69.2.15 84:b8:02:aa:11:03

## ⚙️ Installation

### 1. Télécharger Python
Téléchargez la dernière version stable de Python :  
🔗 https://www.python.org/downloads/

### 2. Installer les dépendances Python

Dans un terminal ou PowerShell :

pip install scapy psutil

## Utilisation

python arp_scan.py