# two-factor-auth — TODO

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
- **CDU-10 / S-76** : `force_two_factor_auth` n'est appliqué que par une redirection
  JavaScript. Le cœur n'offre que des accroches `json.before-<action>` par action : il
  faudrait toutes les énumérer, ou une accroche générique dans `ServiceActions` (cœur).
- **CDU-11 / S-90** : enrôler un secret ne demande pas le mot de passe courant. Demande une
  réauthentification (connexion IMAP fraîche) côté serveur et une invite côté écran.
