# two-factor-auth — TODO

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
