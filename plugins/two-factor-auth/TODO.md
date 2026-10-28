# two-factor-auth — TODO

## 28 octobre 2026 — 2.32.0 déployée sur les deux webmails

À la demande du propriétaire. Procédure du README (« Deploying ») : sauvegardes
`/var/backups/<vhost>/plugins/two-factor-auth.bak-*`, dossier neuf sans `tests/` ni `docs/` posé d'un `mv`,
`restorecon -R` aussitôt, `restart php-fpm`, cache de smail vidé. Vérifié par Apache : version 2.32.0,
`ConfirmBackupCodes` dans le paquet JS, `two-factor-auth` toujours dans `enabled_list`, écrans de connexion
en 200. La production portait exactement la 2.31.0 du dépôt (comparée fichier par fichier avant). **Aucune 2FA
de compte réel touchée, aucun essai en production.**

Relevé en passant : une seule ligne `Maximum execution time of 30 seconds exceeded … index.php on line 278`
(`FilterHttpPaths`) dans `smail-webmail-error.log`, le 28 octobre à 02:20 UTC, **avant** le déploiement. La
fonction ne fait que lire un tableau : c'est la requête entière qui avait épuisé ses 30 s, l'horloge tombant
là par hasard. À surveiller, pas d'action.

## 27 octobre 2026 — 2.32.0 : une clé seule ne doit pas enfermer dehors

* **Le cas** (TODO de la suite §76) : `fbennasr@convergent.tn` n'a plus pu se connecter à
  fastmail. Compte sans TOTP, une clé de sécurité enregistrée le matin, huit codes
  de secours montrés une fois et non gardés. Le soir, sur un autre appareil, la clé
  n'était pas disponible ; les codes à six chiffres tapés venaient d'ailleurs et
  étaient refusés avant le mot de passe. Sa 2FA a dû être remise à zéro côté serveur.
* **Note de conception — le mécanisme retenu : des codes « en attente », prouvés par une
  saisie.**
  * *Ce qui a été choisi.* À l'enregistrement d'une première clé (aucun TOTP actif, aucune
    clé), le serveur ne l'active pas : il la range, scellée, dans `Pending.kb` avec
    huit empreintes de codes neufs (`Pending.h`), un rang à retaper choisi par le
    serveur (`ask`), l'empreinte du jeton de connexion du navigateur (`b`), une
    échéance de 15 min (`e`) et un compteur d'essais (`n`). `DoConfirmBackupCodes`
    reçoit un code ; s'il égale l'empreinte du rang demandé, la clé passe dans
    `PasskeysBox` et les empreintes deviennent `BackupHashes`.
  * *Pourquoi retaper.* Une case « j'ai enregistré mes codes » ne prouve rien : on la
    coche sans lire. Retaper, après que les codes ont quitté l'écran, prouve que la
    personne a **un support où les relire** : papier, gestionnaire de mots de passe.
    Le rang est tiré par le serveur, pour qu'on ne puisse pas répondre « le
    premier » sans la liste. Limite connue : cela prouve qu'on a copié, pas
    qu'on saura retrouver la copie dans six mois.
  * *Pourquoi « en attente » plutôt que « actif, avec un drapeau non confirmé ».*
    Un compte dont la clé est active exige déjà le second facteur à la connexion :
    c'est précisément l'enfermement. En attente, `isOn()` reste faux : la connexion
    est celle d'avant, **rien n'est verrouillé** si la personne s'arrête là, ferme
    l'onglet ou perd les codes. Rien d'actif n'est remplacé non plus.
  * *Pourquoi pas imposer un TOTP* : la demande est de l'**inviter** (avertissement
    permanent, bouton), pas de l'exiger ; certains n'ont pas de téléphone, et les
    codes de secours prouvés sont une sortie suffisante.
  * *Même mécanisme pour « Régénérer les codes »* (`DoRegenerateBackupCodes`, avec un
    facteur courant) : codes en attente **sans clé** ; les anciens valent jusqu'à
    la preuve, de sorte qu'un clic maladroit ne remplace pas des codes gardés par
    des codes perdus.
  * *Une deuxième clé, ou une clé avec un TOTP actif* : actives aussitôt, comme avant
    (un facteur courant est exigé) : les codes existent déjà.
* **Garde-fous de l'action de preuve** (`DoConfirmBackupCodes`, `DoCancelPendingCodes`,
  ouvertes aux comptes qui s'enrôlent) : liée au navigateur qui a vu les codes ;
  5 faux essais jettent les codes (et la clé en attente) ; expiration 15 min ; une
  entrée qui n'est pas une chaîne de 9 chiffres est un faux essai ; un coffre de clé
  altéré n'active rien ; le verrouillage de l'enregistrement n'est pas remis à zéro par
  une confirmation ; S-09 (mots de passe d'application) et S-21 (appareils retenus)
  s'appliquent **à l'activation**, non plus à l'enregistrement.
* **Un greffon enrôlé à demi.** Si un secret TOTP était créé et non activé, la
  confirmation de la clé l'abandonne : ses codes affichés sont remplacés par ceux
  de la clé, il ne pourrait plus s'achever.
* **Écran de connexion** — ce que montrait la 2.31.0 : le bouton « Utiliser une clé de
  sécurité » était déjà présent pour tout visiteur (`TwoFactorKeyLogin`, venu de la
  configuration seule) ; le champ du code ne disait rien d'un code de secours ; le
  rappel (2.30.0) ne s'ajoutait que si le champ du code était **vide**. Le 27 octobre,
  la personne avait tapé de faux codes : pas de rappel. **Changé** : le champ s'appelle
  « Code de vérification ou code de secours » ; **tout** refus 102 ajoute le même
  rappel (avec la clé si les clés sont allumées). Le texte ne dépend ni du compte ni
  du contenu du champ : aucun indice avant le mot de passe, test JS à l'appui.
* ⚠️ **Un bug que les essais unitaires ne voyaient pas, et le banc oui** : les trois
  nouvelles actions n'étaient pas déclarées dans `Init()` (`addJsonHook`). Les tests
  appelaient les méthodes directement ; le navigateur recevait « 999 ». Un test
  vérifie désormais que **chaque** méthode publique `Do*` a son crochet.
* Essais : PHP Actions 303, Record 72, WebAuthn 92 ; JS 51. 25 mutations sur 25 tuées :
  liaison au navigateur, rang demandé, 5 essais, échéance, format du code, secret à
  demi enrôlé, coffre altéré, clé activée à l'enregistrement, régénération sans preuve
  ni sans facteur actif, enregistrement malgré une liaison refusée, actions absentes de
  la liste d'enrôlement, drapeau « clé seule », entrée non-chaîne (avertissement PHP),
  S-09, S-21, rappel conditionné au champ, champ du code, rappel sans la clé, garde
  `Auth`, message d'erreur, codes qui restent à l'écran, drapeau `OnlyKey` ignoré,
  deux crochets absents.
* **Banc** `BANC=cle` sur banc-smail, 70/70 : inscription → codes → faux code refusé →
  bon code → avertissement (rechargé aussi) → connexion avec la clé ; deux refus sans
  facteur, **0 → 0 échec dans l'annuaire**, rappel identique ; en et ar : connexion,
  avertissement, régénération avec la clé et preuve. Compte éphémère supprimé,
  greffon et configuration du banc remis. `forcer` 34/34 ; `avant` 19/19 après avoir
  changé son contrôle (le rappel suit désormais tout refus, code saisi ou non).
* **Pas vérifié** :
  * le rendu sur un téléphone, le lecteur d'écran ;
  * une vraie clé matérielle (le banc utilise l'authentificateur virtuel de Chrome) ;
  * les langues autres que fr, en, ar : elles retombent sur l'anglais ;
  * aucun essai sur fastmail ni smail.tn.
* **Déploiement** : écrit dans le README du greffon (« Deploying »). Rien n'est
  déployé ; le compte du propriétaire n'est pas touché.

## 26 octobre 2026 — 2.31.0 : la clé de sécurité aussi, avant le mot de passe

* **Demandé par le propriétaire** : *« applique la même vérification aux comptes à
  clé de sécurité »*. Jusqu'à la 2.30.0, le défi de la clé ne partait qu'après un
  mot de passe juste. Un compte à clé laissait donc passer son mot de passe vers
  l'annuaire.
* **Fait.** L'écran de connexion demande le défi lui-même, avant tout mot de passe
  (`DoWebAuthnLoginOptions`, ouvert à tous). `CheckBeforePassword` juge ensuite
  l'assertion. Un compte qui a un second facteur et n'en présente aucun est
  refusé, qu'il ait une clé ou non.
* **Les parades de cette action ouverte à tous** :
  * **défi sans état** : 16 octets aléatoires, une expiration (5 min), et un MAC
    (clé tirée d'`APP_SALT`) sur l'adresse et le jeton de connexion du
    navigateur. Rien n'est écrit avant qu'une clé signe : la liste `Challenges`
    de l'enregistrement, plafonnée à 8, ne peut pas être inondée ;
  * **leurres** : une adresse sans clé reçoit 1 ou 2 identifiants tirés d'elle,
    stables, de 64 octets. La forme de la réponse est la même ;
  * **défi dépensé** : son empreinte est gardée jusqu'à son expiration (`Spent`, au
    plus 64). Sans cela, une clé d'accès sans compteur (la plupart) se rejouerait ;
  * **un échec n'écrit rien** ; un succès est rejugé sous le verrou, puis écrit
    (compteur, dernière utilisation, défi dépensé).
* Essais : PHP Actions 254 (+29), JS 39 (+5). 9 mutations sur 9 tuées, dont « défi
  dépensé ignoré ». Celle-ci ne mourait d'abord que par le compteur de la clé ;
  elle est tuée depuis l'ajout du cas d'une clé sans compteur.
* Bancs (banc-smail) :
  * `cle` 39/39 : bouton présent d'emblée, deux refus sans facteur, **0 → 0
    échec dans l'annuaire**, puis connexion par la clé en fr, en et ar ;
  * `avant` 19/19 et `forcer` 34/34.
* ⚠️ **Ce qui reste visible** : le *nombre* et la longueur des identifiants d'un
  vrai compte ne sont pas imités. Seul un authentificateur qui détient la clé
  distingue un leurre ; un observateur voit une ou deux clés dans tous les cas.
* **Allumé sur fastmail le même jour**, demande du propriétaire :
  * `webauthn_origins` = `https://fastmail.convergent.tn` ;
  * `webauthn_rp_id` = `fastmail.convergent.tn`, et non `convergent.tn`. Une clé
    liée à `convergent.tn` répondrait à **tout** sous-domaine de convergent.tn :
    un seul sous-domaine compromis suffirait à lui demander des signatures. Le
    changer plus tard rendrait inutilisables les clés inscrites. smail suit la
    même règle (`webmail.smail.tn`).

## 26 octobre 2026 — 2.30.0 : le code avant le mot de passe (TODO de la suite §72)

* **Fait.** `login.credentials` arme un drapeau, et le `filter.account` qui suit
  (`CheckBeforePassword`) juge le code **avant** `imapConnect`. Ce même
  `filter.account` sert aussi à chaque requête, quand le compte est reconstruit
  depuis son cookie : c'est pourquoi un drapeau est nécessaire. Il est consommé
  par le premier compte filtré, quel qu'il soit (une configuration de compte
  additionnel ne le laisse pas au suivant), et ignoré dans le panneau
  d'administration (`DoAdminDomainMatch` résout aussi des identifiants).
  `DoLogin` (`login.success`) ne rejuge pas un code déjà accepté, sinon il
  l'appellerait un rejeu ; il reste le filet de sécurité pour les clés et pour
  tout chemin qui n'aurait pas armé le drapeau.
* Les parades, chacune tenue par un essai et par une mutation tuée (9 sur 9) :
  1. le refus est celui du cœur pour un mot de passe faux (`AuthError`, sans nom) ;
  2. il attend `precheck_delay` ;
  3. un code faux n'écrit rien, donc aucun verrou ne peut servir d'arme ;
  4. un code juste est rejugé sous le verrou et dépensé ;
  5. un verrou tenu par une autre requête fait refuser le code (`busy`) ;
  6. une assertion ne passe que si le compte a une clé, sinon n'importe quelle
     assertion de pacotille emporterait le mot de passe ;
  7. le panneau d'administration n'est pas pris pour une connexion ;
  8. l'attente est bornée à 10 s.
* **Banc `BANC=avant` (banc-smail, vrai Cyrus, vrai annuaire o=sky), 19/19.** La
  preuve est le compte de l'annuaire lui-même : l'hôte lit les `pwdFailureTime`
  du compte éphémère à chaque étape.
  * Trois refus (bon mot de passe et code faux, mot de passe faux sans code, mot
    de passe faux et code faux) : **0 → 0 échec compté**, chacun refusé en code
    102 sans nom et en 5,0 s.
  * Le témoin (code juste, mot de passe faux) : **0 → 1**, en 5,0 s lui aussi. La
    durée est la même, parce que le `fault_delay` du banc arrondit les deux.
  * Puis la vraie connexion s'ouvre.
  * Bancs `forcer` 34/34 et `cle` 37/37 inchangés.
* Essais : PHP Actions 225 (+31), Record 54, WebAuthn 92 ; JS 34 (+3).
* ⚠️ **Exposition restante, par choix.** Un compte qui a une clé et dont le
  propriétaire n'a pas tapé de code passe encore par le mot de passe d'abord,
  comme avant : émettre le défi avant le mot de passe dirait qui a une clé, et
  ferait écrire l'enregistrement par n'importe qui. IMAP et SMTP directs ne sont
  pas couverts.
* **Pas encore déployé** au moment de cette entrée.


## 13 octobre 2026 — 2.29.0 : les deux restes de la 2.28.0 (A10)

* **Le défi ne s'affiche plus, pas même une image.** Le refus `TwoFactorCodeRequired:`
  porte les options de la clé en base64url ; `Login.js` du cœur l'écrit sous l'erreur
  **dans la même tâche** que l'événement (`fireEvent`, puis `submitError` et
  `submitErrorAdditional`). Le greffon l'effaçait par `setTimeout(…, 0)`, c'est-à-dire
  **après** une occasion de peindre. Désormais `queueMicrotask` : après le code du cœur,
  avant toute peinture. Prouvé dans les deux sens :
  - JS : le contrôle lit le texte à la fin de la file des microtâches — rouge avec
    `setTimeout`, vert avec le correctif. ⚠️ Une première écriture lisait le texte dans un
    `setTimeout` mis en file **après** celui du greffon : elle passait **aussi** avec le
    défaut. *Un contrôle d'ordre se juge contre la règle du navigateur, pas contre une
    autre minuterie* ;
  - banc : un `requestAnimationFrame` compte chaque image peinte où le défi figure —
    avec l'ancien code, **2 échecs sur 3 passages** (en, ar ; le passage fr ne l'a pas
    attrapé : une image se peint ou non selon la charge), 0 avec le correctif.
* **L'écran arabe** : le catalogue `ar` ne portait que 19 clés sur 38 (tout le TOTP venu de
  l'amont tombait en anglais) — complété, et un contrôle exige désormais **les mêmes clés**
  dans `en`, `fr` et `ar`. Les captures arabes ont montré un défaut que rien d'autre ne
  voyait : le champ du nom, **vide**, portait `dir="auto"`, donc `ltr`, et son exemple
  « اسم المفتاح، مثلًا YubiKey أو الهاتف » sortait mots retournés. Le sens n'est plus
  posé que quand le champ a du texte ; vide, il suit la page — contrôlé au banc.
* Banc (`BANC=cle`, banc-smail, authentificateur virtuel) : **37 contrôles, 0 échec**,
  avec deux passages de connexion par clé de plus (anglais, arabe) et leurs réglages.
  JS 31, PHP 92 + Actions + Record, 0 échec. Captures `docs/captures/` (fr, en, ar).
* Déployée sur les deux webmails **sans toucher aux réglages `webauthn_*`** : allumée
  sur webmail.smail.tn (décision du 10 octobre), **éteinte sur fastmail** — l'allumer
  demande au propriétaire de choisir `webauthn_rp_id` (`convergent.tn` ou
  `fastmail.convergent.tn` ; le changer ensuite rend les clés inscrites inutilisables).
* Reste : aucun essai avec une **vraie** clé sur le vrai webmail (seulement
  l'authentificateur virtuel de Chrome et les vecteurs réels du vérificateur).

## 10 octobre 2026 — 2.28.0 : clés de sécurité et clés d'accès (WebAuthn) en second facteur (A10, §60) — **non déployé**

- **Pourquoi un second facteur, et jamais une connexion sans mot de passe** : SnappyMail
  ouvre la boîte en IMAP **avec le mot de passe de la personne**. Une clé d'accès prouve qui
  est au clavier, elle ne donne pas ce mot de passe au serveur. Se connecter avec la clé
  seule obligerait à **conserver les mots de passe côté serveur** (chiffrés, donc
  déchiffrables par le serveur), ou à détenir un **compte maître capable d'ouvrir n'importe
  quelle boîte** (`imapproxy`/SASL proxy-auth) — les deux sont exclus par les règles du
  propriétaire (moindre privilège, aucun secret conservé). Donc : mot de passe d'abord, puis
  le code **ou** la clé. Écrit aussi en tête de `DoLogin()` et dans le `README.md`.
- **Fait** — vérification entièrement côté serveur, **sans dépendance tierce**
  (`providers/webauthn.php`, ~500 lignes) :
  - algorithmes **ES256** (P-256, openssl ; point vérifié sur la courbe), **RS256**
    (2048 à 4096 bits, openssl), **EdDSA** (Ed25519, sodium) ;
  - attestation **`none`** et **`packed`** (auto-attestation vérifiée avec la clé créée ;
    `x5c` vérifiée avec la clé du certificat, **chaîne non approuvée** : l'attestation ne
    sert jamais ici à faire confiance à un modèle, seulement à refuser une déclaration
    fausse) ; tout autre format (`tpm`, `android-key`…) refusé ;
  - **CBOR minimal et borné** : longueurs définies seulement, ni flottant ni étiquette,
    profondeur 8, 64 éléments par conteneur, 512 nœuds, 16 Kio, clé dupliquée refusée,
    clé texte que PHP changerait en entier (`"1"`) refusée ;
  - contrôles : **défi** aléatoire (32 octets), **à usage unique** (dépensé même par un
    échec), **lié au navigateur** (empreinte HMAC du jeton de connexion `smtoken`) **et à
    l'usage** (`login`, `register`, `reauth`), **durée** réglable ; **origine** dans la
    liste configurée (jamais l'en-tête `Host`), `crossOrigin` refusé ; **`rpIdHash`** ;
    drapeaux **UP** (et **UV** si exigé) ; **compteur** de signature qui recule refusé
    (ou journalisé, réglage `warn`) ; la clé doit être **dans la liste du compte** ;
    `userHandle` comparé.
  - **Stockage** : dans le même enregistrement que le TOTP, liste **scellée**
    (`PasskeysBox`, secretbox, clé dérivée d'`APP_SALT`) — une clé publique n'est pas un
    secret, mais qui pourrait **écrire** le stockage ajouterait sinon la sienne au compte
    de n'importe qui. Boîte illisible : la connexion **exige** un second facteur (échec
    fermé), et l'enrôlement imposé la compte comme « non enrôlé ».
- **Connexion** : mot de passe juste et pas de facteur → refus `TwoFactorCodeRequired`
  suivi de `:<options en base64url>` si le compte a une clé — le défi n'est donc émis
  **qu'après un mot de passe juste**. L'écran affiche « Utiliser une clé de sécurité » ;
  l'assertion part dans un champ caché, par le bouton de connexion du cœur. Le code reste
  possible (TOTP s'il est actif, **codes de secours** toujours). Échecs comptés dans le
  **même verrouillage** que les codes (5 en 15 min).
- **Réglages** : liste (nom, ajout, dernière utilisation), ajout, renommage, retrait.
  **Retirer**, ajouter une **deuxième** clé, ajouter un **TOTP** à côté d'une clé, couper le
  TOTP, tout effacer : exigent un **second facteur courant** — code, ou la clé (bouton
  « Utiliser une clé » dans la fenêtre du code). La **première** clé d'un compte donne
  **huit codes de secours**, montrés une fois (sans eux, une clé perdue = une boîte
  perdue). Un TOTP créé à côté d'une clé ne compte **qu'une fois testé**.
  fr/en/ar, garde `Auth`, `unicode-bidi: plaintext` sur les noms et dates, aucune
  expression calculée dans le gabarit, nom de clé nettoyé des caractères de contrôle et de
  forçage bidi (`\p{C}`), 64 au plus.
- **Imposer (2.27.0)** : une clé compte comme enrôlement ; **`DoPluginWebAuthnCreateOptions`
  et `DoPluginWebAuthnRegister`** ajoutés à la liste blanche, **mesurés** sur banc-smail
  (`cle.js`, journal par phase) : rien d'autre n'est appelé pour inscrire une clé.
  S-21 (appareils mémorisés oubliés) et S-09 (mots de passe d'application exigés avant
  activation, relâchés au retrait de la dernière) valent pour les clés.
- **Réglages** (rien en dur) : `webauthn_enabled` (**éteint** par défaut),
  `webauthn_origins` (vide = éteint), `webauthn_rp_id` (vide = hôte de la première
  origine ; une IP est refusée, WebAuthn l'interdit), `webauthn_require_uv`,
  `webauthn_max_passkeys` (10, borné 1–50), `webauthn_challenge_ttl` (300 s, borné
  30–3600), `webauthn_counter_regression` (`refuse`/`warn`).
- **Preuves** :
  - `WebAuthnTest.php` **92** contrôles : clés **engendrées** (openssl, sodium) par un
    authentificateur logiciel écrit d'après la spécification (`tests/authenticator.php`,
    son propre encodeur CBOR), et **sorties d'authentificateurs réels** — vecteurs de
    py_webauthn (Duo Security, BSD-3) : YubiKey `packed` avec certificat (ES256 et
    Ed25519, identifiant de 128 octets), Chrome `none`, assertions ES256 et RS256 réelles.
  - `ActionsTest.php` 194 (+83), `RecordTest.php` 54 (+15), JS **30** (+19, `node:vm`
    sur les vrais fichiers).
  - **Mutations** : 39 contrôles cassés un à un (origine, rpId, UP, UV, défi, type,
    signature, compteur, clé d'un autre compte, userHandle, attestation x5c et auto,
    rawId, point EC, CBOR, liaison/expiration/dépense du défi, verrouillage, preuve exigée
    pour retirer/ajouter, liste blanche, JS) : **37 font tomber 1 à 11 contrôles**. Les 2
    survivants sont **équivalents** (gardés deux fois) : taille RSA (openssl revérifie
    `bits >= 2048`) et longueur d'une chaîne CBOR (la fin d'entrée est revérifiée).
  - **Banc** `BANC=cle sh tests/browser/preparer.sh` sur banc-smail, authentificateur
    virtuel CDP (`WebAuthn.addVirtualAuthenticator`, la pile WebAuthn de Chrome signe
    elle-même) : **22 contrôles, 0 échec** — inscription sous enrôlement imposé, courrier
    refusé avant et servi après, connexion mot de passe + clé, compteur avancé, renommage,
    retrait confirmé par la clé, enrôlement de nouveau exigé. Compte éphémère créé puis
    supprimé, greffon et configuration du banc remis. `forcer.js` (2.27.0) : **34, 0
    échec**. Le banc est joint sous `http://banc-smail.test:8932` (règle de résolution vers
    10.89.10.1, origine déclarée sûre) : WebAuthn refuse une IP comme partie de confiance.
  - Captures : `docs/captures/` (README dedans).
- **Reste / limites** :
  - **Rien de déployé.** Avant la production : poser `webauthn_origins` =
    `https://webmail.smail.tn` (resp. fastmail) et choisir `webauthn_rp_id` (le changer
    plus tard rend toutes les clés inutilisables).
  - Pas de connexion **sans mot de passe** (voir plus haut) ni de clé **découvrable**
    (`residentKey: discouraged`) : voulu.
  - Attestation : chaîne non vérifiée, pas de liste d'AAGUID autorisés ; formats `tpm`,
    `android-key`, `apple`, `fido-u2f` refusés (les navigateurs envoient `none` quand on
    demande `none`, ce qui est le cas).
  - Le défi de connexion voyage dans `messageAdditional` du refus : le cœur l'affiche un
    instant sous l'erreur avant que le greffon ne l'efface (même mécanisme qu'en 2.24.0).
  - La fenêtre de preuve garde le titre « 2-Step verification test » (déjà le cas pour
    « effacer » depuis 2.21.0).
  - Écran arabe non capturé au banc (catalogue complet pour les clés, contrôlé en JS).
  - Pas encore éprouvé avec une **vraie** clé matérielle sur le webmail : vecteurs réels
    au niveau du vérificateur seulement, authentificateur virtuel au banc.

## 10 octobre 2026 — 2.27.0 : « imposer la 2FA » tenu par le serveur (CDU-10 / S-76) — **non déployé**

- **Constat** : jusqu'à 2.26.0, un compte tenu de s'enrôler (interrupteur global ou domaine
  de `force_two_factor_domains`) n'était arrêté que par la redirection de
  `TwoFactorAuthLogin.js` ; sa session lisait le courrier par `?/Json` et `?/Raw` directement.
- **Correctif** : accroche `filter.action-params` (`FilterActionParams`) — le cœur la lance
  avant **chaque** action `?/Json` (POST, et GET à 4 segments ou plus) et **chaque** action
  `?/Raw`. Compte connecté, tenu, sans second facteur actif → toute action hors liste
  blanche est refusée : `ClientException(ClientViewError=902, 'TwoFactorSetupRequired')`.
  902 n'est pas dans la liste du client qui déconnecte après 7 erreurs. Échec fermé : un
  enregistrement illisible compte comme « pas enrôlé ». Jamais pour l'administration
  (`ActionsAdmin`), jamais avant la connexion, jamais pour un compte non tenu — et, sans
  domaine ni interrupteur, la session n'est même pas lue.
- **Les chemins que `filter.action-params` ne voit pas** (cœur 2.38.2), fermés par
  `filter.http-paths` (`FilterHttpPaths`) :
  1. `GET ?/Json/&q[]=/0/<Action>` **à trois segments** : le cœur ne lance pas
     `SetActionParams` (et l'amont n'y vérifie aucun jeton ; le cœur corrigé de la
     production exige `X-SM-Token`, qu'un script tenant la session a). Le greffon ajoute
     un 4ᵉ segment vide → l'accroche tourne (`RawKey` vide = « aucun paramètre »).
  2. tout autre **service** : `Upload`, `UploadContacts`, `UploadBackground`,
     `ProxyExternal`, `Mailto`, et les **parts des autres greffons** (`addPartHook` :
     `CalDavExport`, `CalDavAttachment`, `Files`, `Wopi`…) → réécrit vers la part
     `TwoFactorSetupRequired` du greffon, qui répond 403 + JSON nommé. Seulement si le
     segment désigne vraiment un service du cœur ou une part de greffon (liste privée du
     gestionnaire, lue par `Closure::bind` ; illisible → refusé) : `?lang=fr` ou une faute
     de frappe reçoivent la page, comme avant.
  Restent **ouverts, délibérément** : `AppData` (réglages et identité du compte, pas de
  courrier ; l'application en a besoin pour démarrer), `Plugins`, `Css`, `Lang`, `Ping`
  (du code, pas de données).
- **Liste blanche mesurée** sur banc-smail (`tests/browser/forcer.js`, `MESURE=1`) :
  démarrage forcé → `DoLogin`, **`DoFolders`**, `DoPluginGetTwoFactorInfo` (+ `AccountsAndIdentities`,
  `SMimeGetCertificates`, `SettingsUpdate`, `IdentityUpdate`, greffons `GetVacation`,
  `GetReminders` : refusés sans casser l'écran) ; créer → `DoPluginCreateTwoFactorSecret` ;
  tester/activer → `DoPluginVerifyTwoFactorCode`, `DoPluginEnableTwoFactor` ; déconnexion →
  `DoLogout`. Services : `AppData`, `Plugins`, `Json`.
  ⚠️ **`DoFolders` est obligatoire** : refusé, `App/User.js start()` appelle `logout()` et
  affiche « Folders error » — l'écran d'enrôlement ne serait jamais atteint. Il rend des
  noms de dossiers et des compteurs, aucun message. Ajoutés sans mesure parce qu'ils sont
  sur le même écran : `DoPluginShowTwoFactorSecret`, `DoPluginClearTwoFactorInfo`.
  Défaut : `DoFolders DoLogout DoPluginGetTwoFactorInfo DoPluginCreateTwoFactorSecret
  DoPluginShowTwoFactorSecret DoPluginVerifyTwoFactorCode DoPluginEnableTwoFactor
  DoPluginClearTwoFactorInfo`. Réglable : `setup_allowed_actions`, `setup_allowed_services`
  (vide = défaut mesuré).
- **Après l'activation** : rien n'est mis en cache côté serveur, l'action suivante passe.
  Côté écran, l'activation ne recharge **pas** (les codes de secours sont affichés, une
  seule fois) ; **quitter les réglages recharge l'application une fois**, parce que ce que le
  serveur a refusé au démarrage (identités, données des autres greffons) n'est pas redemandé.
  Effacer ou désactiver la 2FA d'un compte tenu remet `SetupTwoFactor` à vrai.
  Corrigé au passage : un refus sans code d'erreur (`Result: false`) était pris pour une activation.
- **Tests** : `ActionsTest.php` 111 contrôles (+69 : refus de MessageList, Message,
  SendMessage, RawDownload…, liste blanche, GET à trois segments, services, échec fermé,
  enrôlé, non tenu, domaine non listé, interrupteur global, administration, avant connexion
  avec l'état du cœur remis, listes réglables) ; défauts remis un à un (remise de l'état,
  4ᵉ segment, exclusion admin, échec ouvert, services, parts des greffons) : chacun fait
  tomber 1 à 8 contrôles. `RecordTest.php` 39, inchangé.
  JS : 11 (+6). Banc : `sh plugins/two-factor-auth/tests/browser/preparer.sh` → **34
  contrôles, 0 échec** le 10 octobre 2026 (compte éphémère créé puis supprimé, greffon et
  configuration du banc remis).
- **Reste** : l'administration n'a pas pu être éprouvée au navigateur (`allow_admin_panel =
  Off` sur banc-smail) — couverte en PHP seulement. Les réglages autres que la 2FA restent
  joignables pendant l'enrôlement mais leurs enregistrements sont refusés (voulu, échec fermé).
  Un navigateur garde en cache un téléchargement brut reçu **avant** l'effacement de la 2FA
  (en-tête `Expires` du cœur) : ce n'est pas le serveur qui répond.

## 9 octobre 2026 — Audit de sécurité (2.25.0, **non déployé**)

Source : `W/audit-securite-2026-10/RAPPORT.md` §2. Production (fastmail, smail) : 2.24.0.

### S-09 (M) — promesse de mots de passe d'application non tenue — corrigé
- **Cause** : `templates/TwoFactorAuthSettings.html` affichait `APP_PASSWORDS_NOTE` sans
  condition, alors que `appPasswordsRequired()` ne faisait rien quand
  `\Convergent\Appli\Appli` est absente (cas de fastmail : `motsdepasseappli` non déployé).
  Et quand le magasin s'applique mais ne s'écrit pas, l'activation réussissait quand même
  (échec ouvert, seulement journalisé).
- **Correctif** : `FilterAppData` publie `TwoFactorAppPasswords`, vrai seulement si le
  magasin est chargé, la configuration lisible et le domaine du compte servi
  (`appPasswordsConf()`) ; la note est liée à `appPasswordsNote` (relu à chaque `onShow`).
  `appPasswordsRequired()` rend un booléen ; l'exigence est posée **avant** d'activer, et
  son échec **refuse** l'activation (et la relâche si l'enregistrement échoue ensuite).
- **Tests** : `ActionsTest.php` (5 contrôles S-09), `settings.test.js` (2).
- **Reste** : sur fastmail, le mot de passe principal ouvre toujours IMAP/SMTP/DAV pour un
  compte à 2FA — c'est désormais *dit* (rien n'est promis), pas *fermé*. Le fermer =
  déployer `SnappyMail-mots-de-passe-appli` et le relais saslauthd : **décision du
  propriétaire**.

### S-22 (M) — compte protégé ajouté comme compte additionnel — corrigé
- **Cause** : `DoAccountSetup` appelle `LoginProcess(..., false)`, qui n'exécute
  `login.success` que pour le compte principal : `DoLogin` (et le code) était sauté.
- **Correctif** : accroche `filter.account` (`FilterAccount`) : un `AdditionalAccount` dont
  l'enregistrement 2FA (lu **par adresse**, le stockage d'un objet additionnel pointant
  chez le compte principal) est actif est refusé (`TwoFactorNotAdditional`), et la session
  revient au compte principal. L'accroche tourne aussi à chaque reconstruction du compte
  additionnel depuis son cookie : les comptes ajoutés avant ce correctif, ou avant que leur
  titulaire n'active la 2FA, sont fermés aussi.
- **Tests** : `ActionsTest.php` (4 contrôles S-22).
- **Reste** : le dialogue « ajouter un compte » affiche le repère brut
  `TwoFactorNotAdditional` sous « Authentification échouée » (pas d'événement de réponse
  pour le traduire côté greffon). Ajouter un champ de code au dialogue = changement du cœur.

### S-21 (M) — reconnexion « se souvenir de moi » sans second facteur — côté greffon corrigé
- **Cause** : `UserAuth::GetAccountFromSignMeToken()` reconstruit le compte depuis le cookie
  sans passer par `login.success`, et renouvelle le jeton 30 jours à chaque usage ;
  l'activation de la 2FA ne révoquait aucun jeton.
- **Correctif greffon** : `forgetRememberedDevices()` supprime tous les jetons `SIGN_ME` du
  compte quand la 2FA s'active. Un appareil mémorisé ensuite est passé par `DoLogin`,
  code compris.
- **Tests** : `ActionsTest.php` (2 contrôles S-21).
- **Changement du cœur requis : aucun** pour le scénario du rapport (jeton antérieur à
  l'activation). **Recommandé** (session W/secu) : `Logout()` devrait effacer les données
  SignMe (le `TODO` du cœur le dit), et `GetAccountFromSignMeToken()` exécuter une accroche
  (p. ex. `login.sign-me`, avec le compte) pour qu'un greffon puisse refuser un jeton volé ;
  sans elle, un cookie SignMe volé *après* l'activation reste valable jusqu'au changement de
  mot de passe — c'est la nature d'un « appareil de confiance ».

### S-49 (L) — compteur, anti-rejeu et codes de secours sans verrou — corrigé
- **Correctif** : `checkCode()` prend un `flock` exclusif par compte
  (`two_factor.lock` dans le dossier du compte), **relit** l'enregistrement sous le verrou,
  décide, écrit. Verrou introuvable en 3 s : `busy`, jamais `ok` (échec fermé).
  `DoEnableTwoFactor` repart de l'enregistrement relu après `checkCode()`.
- **Tests** : `ActionsTest.php` (4 contrôles S-49, dont la copie périmée qui dépensait deux
  fois un code de secours et contournait le verrouillage).

### Non corrigés (L) — à arbitrer
- **CDU-10 / S-76** : corrigé en **2.27.0**, voir la section du 10 octobre ci-dessous.
- **CDU-11 / S-90** : enrôler un secret ne demande pas le mot de passe courant. Demande une
  réauthentification (connexion IMAP fraîche) côté serveur et une invite côté écran.
