import pytest
from cryptography.exceptions import InvalidTag
from tp1.coffre import chiffrer, dechiffrer

MDP = "MonMotDePasse"
NOM = "facture.txt"
DONNEES = b"Montant: 100 EUR"

def test_aller_retour():
    blob = chiffrer(MDP, NOM, DONNEES)
    assert dechiffrer(MDP, NOM, blob) == DONNEES

def test_chiffrement_probabiliste():
    blob1 = chiffrer(MDP, NOM, DONNEES)
    blob2 = chiffrer(MDP, NOM, DONNEES)
    assert blob1 != blob2
    assert dechiffrer(MDP, NOM, blob1) == DONNEES
    assert dechiffrer(MDP, NOM, blob2) == DONNEES

def test_mauvais_mot_de_passe():
    blob = chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer("MauvaisMotDePasse", NOM, blob)

def test_octet_modifie():
    blob = chiffrer(MDP, NOM, DONNEES)
    modifie = bytearray(blob)
    modifie[50] ^= 1
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, NOM, bytes(modifie))

def test_fichier_renomme():
    blob = chiffrer(MDP, NOM, DONNEES)
    with pytest.raises(InvalidTag):
        dechiffrer(MDP, "autre_nom.txt", blob)
        

def test_rechiffrer():
    from tp1.coffre import rechiffrer
    blob = chiffrer("AncienMDP", NOM, DONNEES)
    nouveau = rechiffrer("AncienMDP", "NouveauMDP", NOM, blob)
    # L'ancien mot de passe ne marche plus
    with pytest.raises(InvalidTag):
        dechiffrer("AncienMDP", NOM, nouveau)
    # Le nouveau marche
    assert dechiffrer("NouveauMDP", NOM, nouveau) == DONNEES