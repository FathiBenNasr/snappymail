# Captures — two-factor-auth

Engendrées par le banc navigateur, jamais prises à la main, sur **banc-smail**
avec un compte éphémère (créé puis supprimé par le banc ; les codes de secours
visibles sont ceux de ce compte, qui n'existe plus) :

    BANC=cle CAPTURES=$PWD/plugins/two-factor-auth/docs/captures \
        sh plugins/two-factor-auth/tests/browser/preparer.sh

| Image | Ce qu'elle montre |
|---|---|
| `avant-1-rappel.png` | (2.30.0, `BANC=avant`) Une connexion envoyée sans code, refusée **comme un mot de passe faux** — rien n'est allé à l'annuaire. Sous le refus, le rappel « saisissez le code avec le mot de passe » : il naît du champ vide, côté navigateur, et s'affiche pour **tout** compte, si bien qu'il ne dit pas qui a un second facteur. |
| `cle-1-reglages.png` | Les réglages juste après l'inscription d'une première clé : la clé listée (nom, date d'ajout, « jamais utilisée »), les huit codes de secours affichés cette seule fois, le champ du nom et « Ajouter une clé de sécurité ». |
| `cle-2-connexion.png` | (2.31.0) L'écran de connexion, adresse et mot de passe saisis : le bouton « Utiliser une clé de sécurité » est là **d'emblée**, pour tout visiteur, partout où les clés sont allumées. Il demande le défi pour l'adresse saisie, puis la clé signe ; le serveur juge la clé **avant** d'envoyer le mot de passe à l'annuaire. |
| `cle-3-retirer.png` | Retirer une clé demande un second facteur courant : un code, ou la clé elle-même (« Use a security key or passkey »). |
| `cle-2-connexion-en.png`, `cle-2-connexion-ar.png` | (2.29.0) Le même écran de connexion en anglais et en arabe — langue prise de `Accept-Language`. En arabe la page et le bouton passent de droite à gauche ; l'adresse latine reste dans son ordre. |
| `cle-1-reglages-en.png`, `cle-1-reglages-ar.png` | (2.29.0) Les réglages en anglais et en arabe — le catalogue arabe est complet (38 clés, il en manquait 19 venues de l'amont) ; le champ du nom, vide, suit le sens de la page, son exemple « YubiKey » au bon endroit. |

⚠️ `preparer.sh` recopie **tout** le dossier de captures du conteneur : des
captures d'un autre banc (`forcer.js`) peuvent s'y trouver. Ne garder que celles
du banc lancé.
