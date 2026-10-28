import os,struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Paramètres Argon2id : temps, mémoire (Kio), parallélisme
T, M, P = 3, 64 * 1024, 4

# Paramètres T, M que j'ai ajustés pour obtenir un temps de calcul d'environ 0,5 s sur ma machine.
T, M = 6, 128 * 1024 

def cle_maitresse(mot_de_passe: str, sel: bytes) -> bytes:
    """Argon2id : mot de passe + sel -> 32 octets de clé maîtresse."""
    return hash_secret_raw(
        secret=mot_de_passe.encode(),
        salt=sel,
        time_cost=T,
        memory_cost=M,
        parallelism=P,
        hash_len=32,
        type=Type.ID,
    )

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256 : clé maîtresse + étiquette d'usage -> 32 octets de sous-clé."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    )
    return hkdf.derive(maitresse)


MAGIC = b"CFR1"
HEADER_LEN = 44

def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    # 1. Sel et nonce neufs à chaque appel
    sel = os.urandom(16)
    nonce = os.urandom(12)

    # 2. En-tête : magic + parametres Argon2id (t, m, p) + sel + nonce
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce

    # 3. Derivation de la cle de chiffrement (usage = "enc")
    maitresse = cle_maitresse(mot_de_passe, sel)
    cle_enc = sous_cle(maitresse, b"enc")

    # 4. Donnees associees = en-tete complet + nom du fichier
    ad = entete + nom.encode()

    # 5. Chiffrement authentifie (AES-256-GCM)
    chiffre = AESGCM(cle_enc).encrypt(nonce, donnees, ad)

    return entete + chiffre

def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    # 1. Verifier la taille minimale et le magic
    if len(blob) < HEADER_LEN or blob[:4] != MAGIC:
        raise ValueError("format inconnu ou tronque")

    # 2. Relire les parametres dans l'en-tete
    t, m, p = struct.unpack(">III", blob[4:16])
    sel = blob[16:32]
    nonce = blob[32:44]
    chiffre = blob[44:]

    # 3. Rederiver avec les parametres stockes (pas les constantes globales !)
    maitresse = hash_secret_raw(
        secret=mot_de_passe.encode(), salt=sel,
        time_cost=t, memory_cost=m, parallelism=p,
        hash_len=32, type=Type.ID,
    )
    cle_enc = sous_cle(maitresse, b"enc")

    # 4. Memes donnees associees qu'au chiffrement
    ad = blob[:HEADER_LEN] + nom.encode()

    # 5. Dechiffrement : leve InvalidTag si modifie
    return AESGCM(cle_enc).decrypt(nonce, chiffre, ad)

def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes) -> bytes:
    """Change le mot de passe d'un fichier chiffre sans changer les donnees."""
    # 1. dechiffre avec l'ancien
    donnees = dechiffrer(ancien_mdp, nom, blob)   
    # 2. rechiffre avec le nouveau
    return chiffrer(nouveau_mdp, nom, donnees)     