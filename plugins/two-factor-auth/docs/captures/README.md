# Captures — two-factor-auth

Engendrées par le banc navigateur, jamais prises à la main (sans suffixe : en français ; `-en` anglais, `-ar` arabe), sur **banc-smail**
avec un compte éphémère (créé puis supprimé par le banc ; les codes de secours
visibles sont ceux de ce compte, qui n'existe plus) :

    BANC=cle CAPTURES=$PWD/plugins/two-factor-auth/docs/captures \
        sh plugins/two-factor-auth/tests/browser/preparer.sh

| Image | Ce qu'elle montre |
|---|---|
| `avant-1-rappel.png` | (2.30.0, `BANC=avant`) Une connexion envoyée sans code, refusée **comme un mot de passe faux** — rien n'est allé à l'annuaire. Sous le refus, le rappel (depuis la 2.32.0 : le code, un code de secours ou la clé) : il s'affiche après **tout** refus, côté navigateur, pour **tout** compte, si bien qu'il ne dit pas qui a un second facteur. |
| `cle-0-note.png` | (2.32.0) Avant d'enregistrer une première clé, sans application à codes : « Cette clé sera votre seul second facteur… ». |
| `cle-1-codes.png`, `-en`, `-ar` | (2.32.0) Les huit codes de secours montrés une fois (masqués dans la capture), et « Je les ai gardés — continuer ». En en/ar, ce sont les codes d'une régénération. |
| `cle-1-preuve.png`, `-en`, `-ar` | (2.32.0) Les codes ont quitté l'écran : la preuve demande le code n° N de la liste ; un faux code est refusé, la clé reste en attente. |
| `cle-1-avertissement.png`, `-en`, `-ar` | (2.32.0) L'avertissement permanent « clé seule », avec le bouton « Ajouter une application à codes ». |
| `cle-1-reglages.png` | Les réglages une fois la première clé activée : la clé listée (nom, date d'ajout, « jamais utilisée »), (depuis la 2.32.0 : l'avertissement « clé seule » et le bouton « Régénérer les codes de secours », les codes n'étant plus affichés qu'avant la preuve) le champ du nom et « Ajouter une clé de sécurité ». |
| `cle-2-connexion.png` | (2.31.0) L'écran de connexion, adresse et mot de passe saisis : le bouton « Utiliser une clé de sécurité » est là **d'emblée**, pour tout visiteur, partout où les clés sont allumées. Il demande le défi pour l'adresse saisie, puis la clé signe ; le serveur juge la clé **avant** d'envoyer le mot de passe à l'annuaire. |
| `cle-3-retirer.png` | Retirer une clé demande un second facteur courant : un code, ou la clé elle-même (« Use a security key or passkey »). |
| `cle-2-connexion-en.png`, `cle-2-connexion-ar.png` | (2.29.0) Le même écran de connexion en anglais et en arabe — langue prise de `Accept-Language`. En arabe la page et le bouton passent de droite à gauche ; l'adresse latine reste dans son ordre. |
| `cle-1-reglages-en.png`, `cle-1-reglages-ar.png` | (2.29.0) Les réglages en anglais et en arabe — le catalogue arabe est complet (38 clés, il en manquait 19 venues de l'amont) ; le champ du nom, vide, suit le sens de la page, son exemple « YubiKey » au bon endroit. |

⚠️ `preparer.sh` recopie **tout** le dossier de captures du conteneur : des
captures d'un autre banc (`forcer.js`) peuvent s'y trouver. Ne garder que celles
du banc lancé.
