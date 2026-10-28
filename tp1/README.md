# TP1 - Coffre chiffré avec mot de passe

## Objectif

Ce projet implémente un petit système de stockage chiffré permettant de :

- protéger des données sensibles par un mot de passe ;
- vérifier leur intégrité ;
- lier le contenu au nom du fichier ;
- changer de mot de passe sans exposer le contenu en clair.

Le code principal se trouve dans `coffre.py` et les tests de validation dans `test_coffre.py`.

## Vue d’ensemble du mécanisme

Le module utilise une combinaison de primitives cryptographiques standards :

- Argon2id pour dériver une clé maîtresse à partir du mot de passe et d’un sel ;
- HKDF-SHA256 pour produire des sous-clés selon l’usage (ex. chiffrement) ;
- AES-GCM pour chiffrer les données et garantir leur authenticité.

Le format produit est un blob binaire contenant un en-tête suivi du ciphertext :

- magic : `CFR1`
- paramètres Argon2id : `T`, `M`, `P`
- sel aléatoire
- nonce AES-GCM
- données chiffrées

Cette structure permet de conserver l’information nécessaire au déchiffrement tout en garantissant l’intégrité du message.

## Installation

Avant de lancer les tests, installer les dépendances :

```bash
pip install -r requirements.txt
```

Si le fichier `requirements.txt` n’est pas encore présent, installer au minimum :

```bash
pip install cryptography argon2-cffi pytest
```

## API publique

### `chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes`

Chiffre un contenu binaire avec le mot de passe fourni.

Paramètres :
- `mot_de_passe` : mot de passe maître
- `nom` : nom associé au fichier ou au document
- `donnees` : contenu brut à protéger

Retour :
- un blob binaire contenant les données chiffrées et leur en-tête

Chaque appel produit un sel et un nonce aléatoires, ce qui rend le chiffrement probabiliste.

### `dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes`

Déchiffre un blob généré par `chiffrer`.

Le déchiffrement vérifie :
- la présence du magic `CFR1` ;
- la taille minimale du format ;
- la validité du tag AES-GCM ;
- l’identité du nom du fichier.

En cas d’échec, une exception `InvalidTag` est levée.

### `rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes`

Permet de changer le mot de passe d’un objet déjà chiffré.

Le principe est simple :
1. déchiffrer avec l’ancien mot de passe ;
2. chiffrer le résultat avec le nouveau mot de passe.

## Exemple d’utilisation

```python
from coffre import chiffrer, dechiffrer, rechiffrer

mot_de_passe = "MonMotDePasse"
nom = "facture.txt"
contenu = b"Montant: 100 EUR"

blob = chiffrer(mot_de_passe, nom, contenu)
print(blob)

restitue = dechiffrer(mot_de_passe, nom, blob)
print(restitue)  # b"Montant: 100 EUR"

nouveau_blob = rechiffrer(mot_de_passe, "NouveauMotDePasse", nom, blob)
restitue_2 = dechiffrer("NouveauMotDePasse", nom, nouveau_blob)
print(restitue_2)
```

## Tests de validation

Le fichier `test_coffre.py` vérifie les propriétés fondamentales du système.

### Liste des tests

- `test_aller_retour` : vérifie qu’un message chiffré puis déchiffré donne exactement le contenu initial.
- `test_chiffrement_probabiliste` : confirme que deux appels successifs au chiffrement du même message produisent deux blobs différents.
- `test_mauvais_mot_de_passe` : vérifie qu’un mot de passe incorrect ne permet pas d’ouvrir le coffre.
- `test_octet_modifie` : détecte toute modification du blob chiffré.
- `test_fichier_renomme` : confirme que le changement de nom du fichier est refusé.
- `test_rechiffrer` : valide le changement de mot de passe sans altérer le contenu.

### Lancer les tests

Depuis le dossier du projet :

```bash
pytest -q test_coffre.py
```

ou :

```bash
python -m pytest -q test_coffre.py
```

### Résultat attendu

Tous les tests doivent passer pour confirmer que le module garantit :

- confidentialité du contenu ;
- intégrité du ciphertext ;
- authenticité du message ;
- lien entre le fichier et son nom.

## Points de sécurité importants

- Le mot de passe ne doit jamais être stocké en clair dans le code ou dans le fichier chiffré.
- Le sel est public et nécessaire : il évite que deux fichiers avec le même mot de passe produisent la même clé.
- Le nonce est aléatoire et doit rester unique pour une même clé.
- Le nom de fichier est inclus dans les données associées pour prévenir les renommages frauduleux.
- L’en-tête est authentifié : une modification de ses paramètres (Argon2id, nonce, sel…) doit être détectée.
- Les erreurs de déchiffrement doivent rester génériques pour éviter les fuites d’information aux attaquants.

## Limites du projet

Ce module est adapté à un usage pédagogique ou à un stockage local simple, mais il ne remplace pas :

- une vraie gestion centralisée de clés ;
- un stockage sécurisé de mots de passe ;
- un système de sauvegarde robuste et protégé ;
- une politique de sécurité complète pour de vrais environnements de production.

## Conclusion

`coffre.py` est un petit coffre-fort cryptographique basé sur Argon2id, HKDF-SHA256 et AES-GCM. Il illustre les concepts fondamentaux de la sécurité : dérivation de clé, authenticité, intégrité et chiffrement symétrique avec données associées.
