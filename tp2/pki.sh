#!/usr/bin/env bash
# pki.sh - Construit l'IGC complete : racine, intermediaire, serveur, client.
# Usage : ./pki.sh
# Prerequis : racine.cnf et inter.cnf dans le dossier courant.

set -euo pipefail   # -e : stop sur erreur ; -u : variable non definie = erreur ; -o pipefail

# --- Verifications preliminaires -------------------------------------------
[ -f racine.cnf ] || { echo "ERREUR : racine.cnf manquant"; exit 1; }
[ -f inter.cnf ]  || { echo "ERREUR : inter.cnf manquant"; exit 1; }

echo "==> Preparation de l'arborescence"
mkdir -p racine/{private,newcerts,crl}
mkdir -p inter/{private,newcerts,crl}
touch racine/index.txt inter/index.txt
echo 1000 > racine/serial
echo 1000 > racine/crlnumber
echo 1000 > inter/serial
echo 1000 > inter/crlnumber

# --- 1. AC racine (P-384, 10 ans) ------------------------------------------
echo "==> Creation de l'AC racine (P-384)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
  -out racine/private/racine.key
chmod 600 racine/private/racine.key

openssl req -x509 -new -key racine/private/racine.key -sha384 -days 3650 \
  -subj "/C=BF/ST=Kadiogo/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out racine/racine.crt

# --- 2. AC intermediaire (P-256, 5 ans) ------------------------------------
echo "==> Creation de l'AC intermediaire (P-256)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out inter/private/inter.key
chmod 600 inter/private/inter.key

openssl req -new -key inter/private/inter.key -sha256 \
  -subj "/C=BF/ST=Kadiogo/O=Universite TP/CN=Intermediaire TP" \
  -out inter/inter.csr

openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# --- 3. Certificat serveur (P-256, 90 jours) -------------------------------
echo "==> Creation du certificat serveur (www.tp.local)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out serveur.key
chmod 600 serveur.key

openssl req -new -key serveur.key -sha256 \
  -subj "/C=BF/ST=Kadiogo/O=Universite TP/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" \
  -out serveur.csr

openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90 \
  -in serveur.csr -out serveur.crt

# --- 4. Certificat client (P-256, 90 jours) --------------------------------
echo "==> Creation du certificat client (alice@tp.local)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out alice.key
chmod 600 alice.key

openssl req -new -key alice.key -sha256 \
  -subj "/C=BF/ST=Kadiogo/O=Universite TP/CN=alice@tp.local" \
  -out alice.csr

openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt

# --- 5. Verification de la chaine ------------------------------------------
echo "==> Verification de la chaine"
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt

echo "==> IGC construite avec succes."
