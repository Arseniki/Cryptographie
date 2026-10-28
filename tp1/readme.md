
1. Pourquoi le sel est-il stocké en clair ? Sa publication affaiblit-elle la sécurité ?
Le sel est stocké en clair car il n'est pas secret : son rôle est d'être unique par fichier pour rendre la dérivation propre à chaque fichier. Le publier n'affaiblit pas la sécurité, car celle-ci repose sur le mot de passe et sur le coût d'Argon2id, pas sur le secret du sel.

Mécanisme : sans sel, deux fichiers protégés par le même mot de passe donnent la même clé ; un attaquant calcule une fois une table précalculée (rainbow table) et casse tous les fichiers d'un coup. Avec un sel aléatoire de 16 octets par fichier, il doit refaire la dérivation pour chaque fichier, ce qui rend l'attaque inexploitable.

Cours : chapitre 2 (KDF, sel, Argon2id) ; chapitre 9 (« sel aléatoire unique par mot de passe contre les tables précalculées »).

2. Le nonce est tiré au hasard sur 96 bits. Pourquoi n'y a-t-il ici aucun risque de répétition, même pour des millions de fichiers ?
Parce que la clé change à chaque fichier : le sel étant neuf, la clé AES-GCM dérivée (HKDF(Argon2id(mdp, sel))) est différente pour chaque fichier. Or la règle GCM impose qu'un nonce ne se répète jamais sous une même clé ; ici, chaque fichier ayant sa propre clé, la contrainte est trivialement satisfaite.

Mécanisme : la borne des 2^32 messages par clé (nonce aléatoire 96 bits) ne s'applique que si la clé est partagée entre messages. Ici, la clé est par fichier, donc la borne ne s'applique pas : même une répétition de nonce entre deux fichiers serait sans effet, car les clés diffèrent.

Cours : chapitre 1 (« ne jamais réutiliser le couple (clé, nonce) ») ; chapitre 3 (« nonce unique, pas forcément secret »).

3. Que se passerait-il si le nom du fichier n'était pas dans les données associées ? Donner un scénario concret.
Un attaquant pourrait renommer un fichier chiffré sans que le déchiffrement échoue. Il n'a pas besoin de la clé : il change seulement le nom du fichier.

Scénario : facture_2025.cfr (chiffré, valide) est renommé en facture_2026.cfr. Sans le nom dans ad, l'étiquette GCM ne dépend pas du nom : le destinataire déchiffre sans erreur et croit à une facture de 2026. Avec le nom dans ad, renommer change ad, donc l'étiquette recalculée diffère : InvalidTag.

Cours : chapitre 3 (AEAD, ad authentifie le contexte : version, identifiant de l'objet, destinataire) ; règle d'ingénieur (« mettre dans les données associées tout le contexte »).

4. Pourquoi l'en-tête lui-même est-il authentifié ? Que pourrait faire un attaquant sinon avec les paramètres Argon2id ?
L'en-tête contient les paramètres Argon2id (t, m, p), relus au déchiffrement pour permettre le durcissement ultérieur. S'il n'était pas authentifié, un attaquant pourrait les affaiblir (par exemple t=1, m=8) pour rendre la dérivation quasi instantanée, puis attaquer le mot de passe par dictionnaire.

Mécanisme : en mettant ad = entete + nom, toute modification de l'en-tête change ad, donc l'étiquette GCM recalculée diffère : InvalidTag. L'attaque par affaiblissement des paramètres échoue.

Cours : chapitre 2 (Argon2id, paramètres stockés) ; chapitre 3 (AEAD, ad authentifie les métadonnées) ; chapitre 9 (attaques par mauvaise configuration).

5. Pourquoi ne doit-on jamais afficher à l'utilisateur la raison précise d'un échec de déchiffrement ?
Parce qu'un message d'erreur précis (« bourrage invalide », « MAC faux », « mauvais mot de passe ») donne à un attaquant un oracle : il distingue les causes d'échec et en déduit de l'information. On renvoie donc un seul message générique (« échec du déchiffrement »), sans détail.

Mécanisme : cette distinction permet de déchiffrer sans la clé (oracle de bourrage CBC, Bleichenbacher sur RSA). Un message unique supprime l'oracle ; la comparaison des étiquettes doit en plus se faire en temps constant (hmac.compare_digest) pour éviter les fuites temporelles.

Cours : chapitre 3 (oracle de bourrage CBC, Bleichenbacher) ; chapitre 9 (« un seul message d'erreur, en temps constant, pour tout échec de déchiffrement »).