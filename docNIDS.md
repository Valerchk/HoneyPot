## Qu'est-ce qu'un NIDS ?

Un **NIDS** (Système de Détection d'Intrusion Réseau) est un outil de sécurité informatique qui surveille en permanence le trafic réseau pour détecter des activités suspectes ou malveillantes.

## Comment fonctionne un NIDS ?

### 1. **Capture du trafic réseau**
- Le NIDS "écoute" tout le trafic qui passe sur le réseau
- Il analyse les paquets de données en temps réel
- Il fonctionne de manière passive (il n'interfère pas avec le trafic)

### 2. **Méthodes de détection**

**Détection par signatures :**
- Compare le trafic à une base de données d'attaques connues
- Comme un antivirus qui reconnaît des virus connus
- Exemple : détecte un scan de ports par sa signature caractéristique

**Détection par anomalies :**
- Apprend le comportement "normal" du réseau
- Alerte quand quelque chose sort de l'ordinaire
- Exemple : trafic inhabituel à 3h du matin

### 3. **Types d'attaques détectées**

- **Scans de ports** : quelqu'un qui "teste" vos services
- **Attaques DDoS** : tentatives de saturer votre réseau
- **Tentatives d'intrusion** : connexions non autorisées
- **Malwares** : logiciels malveillants qui communiquent
- **Exfiltration de données** : vol d'informations

## NIDS dans notre projet

### **Fonctionnalités principales :**
1. **Capture les paquets** avec des bibliothèques comme `scapy`
2. **Analyse en temps réel** le contenu des paquets
3. **Détecte des patterns suspects** (signatures d'attaques)
4. **Génère des alertes** quand une menace est identifiée

### **Exemple concret :**

#  NIDS pourrait détecter :
- Un scan de ports : beaucoup de connexions vers différents ports
- Une attaque par force brute : multiples tentatives de connexion
- Du trafic anormal : paquets de taille inhabituelle

## Avantages et limites

### **Avantages :**
- Surveillance continue
- Détection rapide des menaces
- Vision globale du réseau
- Logs détaillés pour analyse

### **Limites :**
- Ne peut pas arrêter une attaque (seulement alerter)
- Possible faux positifs
- Performance impactée sur gros réseaux
- Difficulté avec le trafic chiffré

## Lien avec notre SAE

Le **honeypot (T-pot)** attire les attaquants, et votre **NIDS** détecte leurs actions. C'est complémentaire :
- Le honeypot = "piège" pour attirer
- Le NIDS = "gardien" qui surveille et alerte