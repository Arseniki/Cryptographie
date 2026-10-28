#!/usr/bin/env bash
set -euo pipefail

[ -f racine.cnf ] || { echo "ERREUR : racine.cnf manquant"; exit 1; }
[ -f inter.cnf ]  || { echo "ERREUR : inter.cnf manquant"; exit 1; }

echo "==> Preparation de l'arborescence"
mkdir -p racine/{certs,crl,newcerts} inter/{certs,crl,newcerts}
: > racine/index.txt
: > inter/index.txt
echo 1000 > racine/serial; echo 1000 > racine/crlnumber
echo 2000 > inter/serial;  echo 2000 > inter/crlnumber

echo "==> AC racine (P-384)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

echo "==> AC intermediaire (P-256)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -sha256 \
  -subj "/C=BF/O=Universite TP/CN=Intermediaire TP" -out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

echo "==> Certificat serveur (www.tp.local)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
chmod 600 serveur.key
openssl req -new -key serveur.key -sha256 \
  -subj "/C=BF/O=Universite TP/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_server -days 90 \
  -in serveur.csr -out serveur.crt

echo "==> Certificat client (alice@tp.local)"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
chmod 600 alice.key
openssl req -new -key alice.key -sha256 \
  -subj "/C=BF/O=Universite TP/CN=alice@tp.local" -out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90 \
  -in alice.csr -out alice.crt

echo "==> Verification de la chaine"
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt
echo "==> IGC construite avec succes."