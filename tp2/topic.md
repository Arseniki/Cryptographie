3 TP 2 – Construire une infrastructure de gestion de clés (3 h)
3.1 Objectifs
À la fin du TP, vous saurez :
— créer une AC (autorité de certification) racine et une AC intermédiaire avec les bonnes
extensions ;
— émettre des certificats de serveur et de client à partir de demandes de certificat (CSR (Cer-
tificate Signing Request, demande de signature de certificat)) ;
— valider une chaîne de certificats et en comprendre chaque contrôle ;
— révoquer un certificat et publier une liste de révocation (CRL (Certificate Revocation List,
liste de certificats révoqués)) ;
— restreindre une AC intermédiaire par des contraintes de nom.
3.2 Architecture visée
ÉlémentClé et duréeExtensions essentielles
AC racineP-384, 10 ans, hors ligneAC intermédiaireP-256, 5 ansServeur
www.tp.local
Client
alice@tp.localP-256, 90 joursCA:TRUE, pathlen:1 ; signature de
certificats et de CRL
CA:TRUE, pathlen:0 ; contraintes
de nom limitées à tp.local
CA:FALSE ; usage « serveur TLS » ;
noms alternatifs
CA:FALSE ; usage « client TLS »
P-256, 90 jours

3.3 Travail demandé
Étape 1 – Préparer les autorités (30 min). Créer l’arborescence et les deux fichiers de confi-
guration fournis (racine.cnf et inter.cnf, voir l’annexe B). Pour chaque section d’extensions,
expliquer dans le compte rendu le rôle de chaque ligne.
Étape 2 – AC racine (20 min).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
-out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
-subj "/C=BF/O=Universite TP/CN=Racine TP" \
-addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
-addext "keyUsage=critical,keyCertSign,cRLSign" \
-addext "subjectKeyIdentifier=hash" -out racine/racine.crt
openssl x509 -in racine/racine.crt -noout -text
Repérer dans la sortie : émetteur, sujet, validité, algorithme de clé, extensions critiques. Pourquoi
l’émetteur et le sujet sont-ils identiques ?
Étape 3 – AC intermédiaire (30 min). Générer la clé et la demande de certificat de
l’intermédiaire, puis la faire signer par la racine :
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
-in inter/inter.csr -out inter/inter.crt
Vérifier la présence des contraintes de nom et de pathlen:0.
Étape 4 – Certificats de serveur et de client (35 min). Le demandeur génère sa propre
clé et sa demande ; l’AC intermédiaire signe. Pour le serveur :
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
-addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
-in serveur.csr -out serveur.crt
Faire de même pour le client alice@tp.local avec la section ext_client.
Étape 5 – Valider (25 min). Exécuter et interpréter :
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
-verify_hostname www.tp.local serveur.crt
# attendu : OK
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
-verify_hostname autre.example serveur.crt
# attendu : echec
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
-purpose sslclient alice.crt
# attendu : OK
Puis demander à l’intermédiaire un certificat pour www.example.com, et vérifier que la validation
échoue (« permitted subtree violation »). Expliquer pourquoi l’AC a pu signer ce certificat alors
qu’il est refusé à la validation.
Étape 6 – Révoquer (25 min). On suppose que la clé d’Alice a été compromise.
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt \
-untrusted inter/inter.crt alice.crt
# attendu : revoked
openssl crl -in inter/crl/inter.crl -noout -text
Étape 7 – Automatiser (15 min). Regrouper les étapes 2 à 4 dans un script pki.sh qui
s’arrête à la première erreur (set -euo pipefail).
3.4 Questions de réflexion
Questions
1. Pourquoi la clé de la racine doit-elle rester hors ligne ? Que faut-il faire si l’intermédiaire
est compromis ? Et la racine ?
2. À quoi sert pathlen:0 sur l’intermédiaire ? Quel risque si on l’oublie ?
3. Pourquoi la clé privée du serveur est-elle générée par le serveur et non par l’AC ?
4. Le nom commun (CN (Common Name, nom commun)) du certificat et le champ
des noms alternatifs (SAN (Subject Alternative Name, noms alternatifs du sujet))
contiennent tous deux www.tp.local. Lequel les clients modernes vérifient-ils ?
5. Quelles sont les limites des CRL ? Comparer avec OCSP (Online Certificate Status
Protocol, protocole de vérification en ligne de l’état d’un certificat) et avec des certificats
de très courte durée.
6. Rédiger en dix lignes une politique de certification minimale pour cette infrastructure
(qui peut demander, comment l’identité est vérifiée, durées, révocation).
Livrable et barème
Le script pki.sh, les deux fichiers de configuration, les certificats publics (jamais les clés
privées) et un compte rendu de trois pages.
Barème (20 points) : racine et intermédiaire 5 ; certificats feuilles 4 ; validations com-
mentées 4 ; révocation 3 ; script 1 ; questions 3.