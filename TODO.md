# TODO — fork du cœur SnappyMail, branche `securite/2.38.2`

## 9 octobre 2026 — Audit de sécurité

Source : `W/audit-securite-2026-10/RAPPORT.md` §2. **Rien de ceci n'est déployé.**
Tests : `for f in test/*.php; do php $f; done` (10 scripts verts ; `carddav.php`,
`sasl.php` et `sso.php` sont des scripts d'amont qui ne tournent pas hors application,
avant comme après) et `node --test securite/*.test.js` (avec
`JS_DIR=<copie de static/js patchée>` pour les fichiers compilés).

### S-01 (C) — backup : restauration sans administrateur, zip slip, PHP écrasé
- **Cause** : `JsonAdminRestoreData` ne testait que `instanceof ActionsAdmin`, qui se
  construit sur l'URL seule, y compris pour un anonyme ; le garde du cœur ne couvre que
  les actions `Admin…`, pas `Plugin…`. Puis `extractTo(APP_PRIVATE_DATA)` sans contrôle
  des noms, type MIME fourni par le client.
- **Correctif** (`plugins/backup/index.php`, 1.2 → **1.3**) : `adminLoggedIn()`
  (`IsAdminLoggined(false)`, strictement `true`) pour les deux actions, **avant** de
  regarder l'envoi ; MIME client ignoré, `ZipArchive::open(RDONLY|CHECKCONS)` ; chaque
  entrée validée avant toute écriture (absolu, `..`, `.`, `\`, `:`, octets de contrôle,
  lien symbolique, hors de `configs/ domains/ plugins/ storage/ AddressBook.sqlite`) —
  un seul refus rejette l'archive entière, rien n'est écrit ; les fichiers de code
  (`.php*`, `.phtml`, `.phar`, `.ht*`, `.user.ini`) ne sont **jamais** écrits, ils sont
  listés dans `skipped`. Branche `PharData` (variable non définie) retirée.
- **Test** : `test/backup-restore.php` (45 contrôles ; rouge sur l'ancien fichier).
- **Production** : `plugins/backup/index.php` déployé est **identique** à la 1.2 de ce
  dépôt (même `VERSION`, `diff` vide). Le greffon est actif ; tant que la 1.3 n'est pas
  déposée, la faille est ouverte.
- **Reste** : le garde du cœur lui-même (toute action de greffon appelée depuis
  `?admin` sans session) relève de S-11, non traité ici.

### S-06 (H) — CardDAV / client DAV : SSRF, http, TLS non vérifié
- **Cause** : URL de synchro libre (et les `href` renvoyés par le serveur distant),
  `setVerifyPeer(false)` en dur, `http://` accepté, jamais `block_private_ips`.
- **Correctif** :
  - `CardDAV.php` : `davUrlRefusal()` — https seul ; hôte hors liste → adresses
    publiques seulement ; `setVerifyPeer(true)` ; `getDavClientFromUrl()` rend `null`
    (journalisé) au lieu d'un client.
  - `dav/client.php` : `block_private_ips` et `verify_peer` **vrais par défaut**
    (échec fermé), levés seulement par `allowPrivateHosts`.
  - `http/request.php` : `ResolvePublicHost()` rend les adresses vérifiées ; plages
    ajoutées (0/8, 240/4, TEST-NET, `2001:db8::/32` que PHP 8.5 laisse passer,
    `64:ff9b:1::/48`, `100::/64`, et lo/lien-local/ULA répétés pour ne pas dépendre de
    la version de PHP).
  - `request/curl.php` et `request/socket.php` : **épinglage** — l'adresse vérifiée est
    celle de la connexion (`CURLOPT_RESOLVE` / connexion à l'IP + `peer_name`). Ferme
    au passage **S-42** (rebinding du proxy d'images, qui pose `block_private_ips`).
  - Redirections : `max_redirects = 0` et la 301 du client DAV reste sur l'hôte de base,
    revérifié à chaque requête.
  - `Contacts.php` : le mot de passe stocké n'est plus gardé (`APP_DUMMY`) si l'URL change.
  - `Application.php` : nouvelle clé `[contacts] sync_allowed_hosts`.
- **Test** : `test/dav-ssrf.php` (37) et `test/ssrf-ranges.php` complété (rouge sur
  l'ancien `request.php` : `[2001:db8::1]` passait). Le voisin de « l'adresse de cet
  hôte » y est désormais une adresse publique, les plages de documentation étant refusées.
- ⚠️ **Décision avant dépôt** : les deux webmails synchronisent vers **leur propre
  Cyrus**, donc une adresse interne — `pim.convergent.cc` est une adresse de cet hôte,
  `smail-local.convergent.cc` vaut 127.0.0.1. Sans
  `sync_allowed_hosts = "pim.convergent.cc"` (fastmail) et
  `sync_allowed_hosts = "smail-local.convergent.cc:8008"` (smail) dans
  `application.ini`, **toute synchro de contacts cessera**. Et le TLS étant désormais
  vérifié, les deux certificats doivent l'être aussi — **à vérifier au banc**.
- **Reste** : `plugin-caldav-plugin#11` (CalDAV hérite de l'hôte de `contacts_sync`)
  est dans le dépôt du greffon CalDAV.

### S-14 (M) — cache JS/CSS des greffons sans portée
- **Cause** : clé `PluginsJsCache(hash)` et `/CssCache/hash/thème/` identiques pour
  `?/Plugins/0/Admin/` et `?/Plugins/0/` ; un GET anonyme sur cache froid empoisonnait
  le paquet de tous les utilisateurs.
- **Correctif** : `KeyPathHelper::PluginsJsCache($hash, $bAdmin)` et `CssCache(…,
  $bAdmin)`, utilisés par `ServicePlugins()` / `ServiceCss()`.
- **Test** : `test/plugins-cache-scope.php` (8, dont une lecture de la source de
  `ServiceActions.php`).
- **Reste** : le paquet admin reste lisible par un anonyme (il l'était déjà ; l'écran
  de connexion de l'administration en a besoin). Effet de bord au dépôt : la clé
  change, le cache se reconstruit — et cela **lève l'empoisonnement du panneau
  d'administration** décrit dans `SnappyMail/CLAUDE.md`.

### S-19 (M) — plainToHtml : un guillemet sort de `href`
- **Cause** : seuls `& < >` étaient échappés ; `"style=…"@x.tn` (ou une URL dont
  `stripTracking()` ne sait pas lire l'hôte) refermait l'attribut.
- **Correctif** : `dev/Common/Html.js` — `"` → `&quot;` dans les deux `href` ; le texte
  du lien est inchangé. Compilés : **`securite/html-js.py` porte les quatre ancres
  nouvelles** (app.js et min/app.min.js), même méthode que le report Tachyon.
  `Actions.php` : `?r=securite-20261007` → **`?r=securite-20261009`** (cache d'un an).
- **Build** : non lancé — pas de `node_modules`, et le paquet 2.38.2 ne se reconstruit
  pas à l'identique (déjà constaté le 7 octobre). Le script a été éprouvé sur une copie
  des fichiers de production (idempotent, `--verifier`, `node --check` vert).
  ⚠️ Au dépôt : régénérer **`app.min.js.gz` / `.br` et `app.js.gz` / `.br`**, sinon le
  serveur sert la version précompressée d'avant.
- **Test** : `securite/plain-to-html.test.js` — la source chargée dans `vm` (4 tests ;
  rouges sur l'ancienne source et sur les compilés non patchés).

### S-21 (M) — reconnexion « se souvenir de moi » sans second facteur
- **Le correctif appartient au greffon `two-factor-auth`** (W/2fa, non touché ici) :
  à l'activation du second facteur, révoquer les jetons SignMe du compte.
- **Ce que le cœur apporte** : `UserAuth::ClearAllSignMeTokens(MainAccount)` — supprime
  la moitié serveur de **tous** les jetons du compte (`.sign_me/`), ce qui rend chaque
  cookie inutilisable. ⚠️ Le correctif proposé par le rapport,
  `Clear($oAccount, SIGN_ME, '')`, **ne révoque rien** : clé vide → le nom de fichier est
  le dossier, et `unlink()` échoue (prouvé par le test).
- **Test** : `test/signme-revoke.php` (9).
- **Reste, côté greffon** : appeler
  `$this->Manager()->Actions()->ClearAllSignMeTokens($oAccount)` dans
  `DoEnableTwoFactor()` après enregistrement réussi (et à la réinitialisation) ; un
  changement de mot de passe devrait faire de même.

### Constats L du cœur, non traités ici
S-39 (DKIM du dernier Authentication-Results), S-40 (promesse `verified` d'OpenPGP.js),
S-41 (SVG distants sans CSP sandbox), S-43 (garde « adresse publique » recopiée dans les
greffons — la version du cœur est complétée ci-dessus, les copies restent), S-44
(`srcset` déjà retiré par fd445f19c ; `border-image-source:url()` couvert par la même
boucle — à confirmer au banc). S-42 est fermé par l'épinglage de S-06.
