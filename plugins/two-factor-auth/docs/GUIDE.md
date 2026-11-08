# Guide de l'utilisateur — la validation en deux étapes

La validation en deux étapes protège votre compte même si quelqu'un apprend votre mot de passe : à la
connexion, le webmail demande en plus un code de votre téléphone, ou votre clé de sécurité. Tout se règle
dans **Réglages**, onglet **Authentification en deux étapes**.

## Activer la validation avec une application à codes

**À quoi ça sert :** demander, à chaque connexion, un code à six chiffres que seule votre application
connaît (Google Authenticator, Microsoft Authenticator, FreeOTP…).

1. Installez une application à codes sur votre téléphone.
2. Dans le webmail, ouvrez **Réglages**, puis **Authentification en deux étapes**.
3. Cliquez sur **Activer**. Un code QR s'affiche.
4. Dans l'application du téléphone, ajoutez un compte en photographiant le code QR.
5. Cliquez sur **test**, puis saisissez le code que l'application affiche.
6. Notez vos **codes de secours** et gardez-les en lieu sûr (voir [« Garder ses codes de secours »](#garder-ses-codes-de-secours)).
7. Cochez **Activer l'authentification en deux étapes**.

**Résultat :** à la prochaine connexion, le webmail demande le code de l'application en plus du mot de
passe. Si votre webmail propose **Mots de passe d'application**, vos logiciels de courrier (téléphone,
Thunderbird, Outlook) en demandent un à la place de votre mot de passe : créez-les d'abord. Tant que cette case n'est pas cochée, votre compte n'est pas protégé.

## Se connecter avec le code

**À quoi ça sert :** ouvrir sa session quand la validation en deux étapes est active.

1. Sur l'écran de connexion, saisissez votre adresse et votre mot de passe.
2. Dans le champ **Code de vérification ou code de secours**, tapez le code que l'application affiche.
3. Validez.

**Résultat :** vous êtes connecté. Un code ne sert qu'une fois et change toutes les 30 secondes.

![Un refus à la connexion, et le rappel du code](captures/avant-1-rappel.png)

Si la connexion est refusée, le webmail rappelle qu'il faut aussi le code, un code de secours ou la clé. Le
même message s'affiche pour tout le monde : il ne dit pas si un compte a la validation en deux étapes.

## Ajouter une clé de sécurité ou une clé d'accès

**À quoi ça sert :** confirmer la connexion en touchant une clé (YubiKey…) ou par l'empreinte de votre
téléphone ou de votre ordinateur, sans taper de code.

1. Ouvrez **Réglages**, puis **Authentification en deux étapes**.
2. Sous **Clés de sécurité et clés d'accès**, donnez un nom à la clé, par exemple « YubiKey » ou
   « téléphone ».
3. Cliquez sur **Ajouter une clé de sécurité**, puis touchez la clé ou confirmez sur l'appareil.

![Les réglages avec une clé enregistrée](captures/cle-1-reglages.png)

**Résultat :** la clé apparaît dans la liste, avec son nom, sa date d'ajout et sa dernière utilisation.

Si c'est votre première clé et que vous n'avez pas d'application à codes, le webmail vous prévient :

![« Cette clé sera votre seul second facteur »](captures/cle-0-note.png)

Il vous montre alors vos codes de secours avant d'activer la clé : c'est ce qui vous ouvrira le compte si la
clé n'est pas avec vous.

## Garder ses codes de secours

**À quoi ça sert :** entrer dans votre compte le jour où vous n'avez ni votre téléphone ni votre clé.

1. Quand le webmail affiche vos huit codes de secours, notez-les ou enregistrez-les dans un gestionnaire de
   mots de passe. Ils ne sont montrés qu'une fois.
2. Cliquez sur **Je les ai gardés - continuer**. Les codes disparaissent de l'écran.
3. Le webmail demande **Retapez le code de secours n° … de votre liste** : tapez ce code, puis
   **Confirmer**.

![Les codes de secours, montrés une fois](captures/cle-1-codes.png)

![La confirmation par un des codes](captures/cle-1-preuve.png)

**Résultat :** la clé ou les nouveaux codes deviennent actifs. Tant que vous n'avez pas confirmé, rien ne
change pour votre compte. **Annuler et recommencer** produit une nouvelle liste.

## Se connecter avec une clé de sécurité

**À quoi ça sert :** ouvrir sa session d'un geste, sans taper de code.

1. Sur l'écran de connexion, saisissez votre adresse et votre mot de passe.
2. Cliquez sur **Utiliser une clé de sécurité ou une clé d'accès**.
3. Touchez la clé, ou confirmez sur votre appareil.

![Le bouton de la clé sur l'écran de connexion](captures/cle-2-connexion.png)

**Résultat :** vous êtes connecté. Votre mot de passe reste demandé : la clé est la deuxième étape, pas un
remplacement.

## Se connecter avec un code de secours

**À quoi ça sert :** entrer dans son compte sans son téléphone ni sa clé.

1. Sur l'écran de connexion, saisissez votre adresse et votre mot de passe.
2. Dans le champ **Code de vérification ou code de secours**, tapez un de vos codes de secours.

**Résultat :** vous êtes connecté, et ce code ne servira plus. Le nombre de codes qui restent s'affiche dans
**Codes de secours restants**.

## Recevoir le code sur son adresse de secours

**À quoi ça sert :** se connecter avec un code reçu par courriel, sans application à codes. C'est plus simple,
mais moins sûr : qui lit votre boîte de secours reçoit aussi vos codes.

1. Vérifiez d'abord votre adresse de secours dans **Ma formule** : elle doit être sur un autre domaine que votre
   compte, et confirmée.
2. Ouvrez **Réglages**, puis **Authentification en deux étapes**, section **Code par l'adresse de secours**.
3. Cliquez sur **Envoyer un code pour l'activer**, puis tapez le code de 8 chiffres reçu et cliquez sur **Activer**.
4. Si c'est votre premier second facteur, gardez les codes de secours affichés et confirmez-les comme dans
   [« Garder ses codes de secours »](#garder-ses-codes-de-secours).

![La section « Code par l'adresse de secours », activée](captures/courriel-2-active.png)

**Résultat :** **Activé** s'affiche à côté de l'adresse masquée.

Si la section n'apparaît pas, votre organisation a peut-être choisi de ne pas accepter ce code : utilisez une
application à codes ou une clé de sécurité.

## Se connecter avec un code reçu par courriel

**À quoi ça sert :** ouvrir votre session quand vous n'avez pas votre application d'authentification sous la main.

![Le bouton sur l'écran de connexion](captures/courriel-3-connexion.png)

1. Sur l'écran de connexion, saisissez votre adresse, puis cliquez sur **Recevoir un code sur mon adresse de
   secours**.
2. Ouvrez votre boîte de secours, puis tapez le code de 8 chiffres dans **Code de vérification ou code de
   secours**, avec votre mot de passe.

**Résultat :** vous êtes connecté. Le code vaut 10 minutes, une seule fois, dans le navigateur qui l'a demandé.
Au plus trois codes par quart d'heure : au-delà, attendez ou utilisez un code de secours.

## Régénérer ses codes de secours

**À quoi ça sert :** obtenir une nouvelle liste quand vous avez utilisé presque tous vos codes, ou perdu la
liste.

1. Ouvrez **Réglages**, puis **Authentification en deux étapes**.
2. Cliquez sur **Régénérer les codes de secours**, puis confirmez avec votre code ou votre clé.
3. Gardez la nouvelle liste et confirmez-la comme dans [« Garder ses codes de secours »](#garder-ses-codes-de-secours).

**Résultat :** huit nouveaux codes. Les anciens restent valables jusqu'à la confirmation des nouveaux.

## Quand la clé est votre seul second facteur

**À quoi ça sert :** ne pas perdre l'accès à votre compte le jour où la clé n'est pas avec vous.

Tant que vous n'avez qu'une clé, sans application à codes, un avertissement reste affiché dans les
réglages :

![L'avertissement « clé seule »](captures/cle-1-avertissement.png)

1. Cliquez sur **Ajouter une application à codes**.
2. Suivez les étapes de « Activer la validation avec une application à codes ».

**Résultat :** vous avez une seconde voie d'accès, et l'avertissement disparaît.

## Retirer une clé

**À quoi ça sert :** ne plus accepter une clé perdue ou remplacée.

1. Ouvrez **Réglages**, puis **Authentification en deux étapes**.
2. À côté de la clé, cliquez sur **Retirer**.
3. Confirmez avec un code, ou avec la clé elle-même.

![Retirer une clé demande une confirmation](captures/cle-3-retirer.png)

**Résultat :** la clé ne permet plus de se connecter. Une personne qui aurait volé votre session ne peut pas
retirer vos protections sans votre code ou votre clé.

## Désactiver la validation en deux étapes

**À quoi ça sert :** revenir au mot de passe seul, par exemple si vous changez de façon de vous protéger.

**Attention :** tant que la validation est désactivée, le mot de passe suffit à ouvrir votre compte. Si votre organisation
l'exige, le webmail vous demandera de la remettre en place.

1. Ouvrez **Réglages**, puis **Authentification en deux étapes**.
2. Décochez **Activer l'authentification en deux étapes**.
3. Dans la fenêtre **Test d'authentification en deux étapes**, tapez un code de votre application, ou un code de
   secours, dans **Code**, puis cliquez sur **Test**. Si vous avez une clé de sécurité, vous pouvez cliquer sur
   **Utiliser une clé de sécurité ou une clé d'accès** à la place.

**Résultat :** la case est décochée, et le webmail ne demande plus de code à la connexion. Sans le code ou la clé, la
case ne se décoche pas : c'est voulu, pour qu'une personne qui aurait pris votre session ne puisse pas retirer la
protection.

## Changer de téléphone

**À quoi ça sert :** continuer à vous connecter avec un nouveau téléphone, sans perdre l'accès à votre compte.

**Attention :** **Vider** efface la validation en deux étapes en entier : la clé secrète, vos codes de secours et vos
clés de sécurité. Tant que vous n'avez pas fini les étapes ci-dessous, votre compte n'est protégé que par son mot de
passe. Gardez l'ancien téléphone à portée de main jusqu'au bout.

1. Ouvrez **Réglages**, puis **Authentification en deux étapes**.
2. Cliquez sur **Vider**, puis tapez un code de l'ancien téléphone, ou un code de secours, dans **Code**, et cliquez sur
   **Test**.
3. Cliquez sur **Activer**. Un nouveau code QR s'affiche, avec de nouveaux codes de secours.
4. Sur le nouveau téléphone, ajoutez un compte dans l'application à codes en photographiant ce code QR.
5. Cliquez sur **test**, saisissez le code que le nouveau téléphone affiche, puis cochez **Activer l'authentification
   en deux étapes**.
6. Notez les nouveaux codes de secours (voir [« Garder ses codes de secours »](#garder-ses-codes-de-secours)) : les
   anciens ne servent plus. Si vous aviez des clés de sécurité, ajoutez-les de nouveau.

**Résultat :** le nouveau téléphone donne les codes, et l'ancien n'en donne plus de valables.

## Questions fréquentes

**J'ai perdu mon téléphone.**
Connectez-vous avec un code de secours, puis créez une nouvelle clé secrète dans les réglages pour votre
nouveau téléphone.

**Je n'ai plus ni téléphone, ni clé, ni codes de secours.**
Adressez-vous à votre administrateur : il peut, après vérification, remettre à zéro votre validation en
deux étapes.

**Le code est refusé alors que je le tape bien.**
Vérifiez que l'heure de votre téléphone est réglée automatiquement : un code dépend de l'heure. Vérifiez
aussi que vous lisez le bon compte dans l'application.

**Après plusieurs essais, plus rien ne passe.**
Après plusieurs échecs, les essais sont bloqués un moment, même avec un bon code. Attendez un
quart d'heure.

**Mon téléphone ou Thunderbird ne reçoit plus le courrier.**
Si votre webmail propose **Mots de passe d'application**, ces logiciels en demandent un à la place de votre
mot de passe : créez-en un par appareil. Sinon, adressez-vous à votre administrateur.
