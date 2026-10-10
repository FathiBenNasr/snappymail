# Captures — two-factor-auth

Engendrées par le banc navigateur, jamais prises à la main, sur **banc-smail**
avec un compte éphémère (créé puis supprimé par le banc ; les codes de secours
visibles sont ceux de ce compte, qui n'existe plus) :

    BANC=cle CAPTURES=$PWD/plugins/two-factor-auth/docs/captures \
        sh plugins/two-factor-auth/tests/browser/preparer.sh

| Image | Ce qu'elle montre |
|---|---|
| `cle-1-reglages.png` | Les réglages juste après l'inscription d'une première clé : la clé listée (nom, date d'ajout, « jamais utilisée »), les huit codes de secours affichés cette seule fois, le champ du nom et « Ajouter une clé de sécurité ». |
| `cle-2-connexion.png` | L'écran de connexion après un mot de passe juste : le message nomme le code **et** la clé, et le bouton « Utiliser une clé de sécurité » est apparu (il n'existe pas pour un compte sans clé). |
| `cle-3-retirer.png` | Retirer une clé demande un second facteur courant : un code, ou la clé elle-même (« Use a security key or passkey »). |

⚠️ `preparer.sh` recopie **tout** le dossier de captures du conteneur : des
captures d'un autre banc (`forcer.js`) peuvent s'y trouver. Ne garder que celles
du banc lancé.
