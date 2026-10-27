# two-factor-auth — journal des versions

Les versions antérieures à 2.30.0 sont décrites, avec leurs mesures, dans
[`TODO.md`](TODO.md).

## 2.32.0 — 27 octobre 2026

* **Une clé de sécurité seule ne peut plus vous enfermer dehors sans que vous l'ayez
  voulu.** Quand aucune application à codes n'est active, l'enregistrement d'une
  première clé dit : « Cette clé sera votre seul second facteur : sans elle, seuls
  vos codes de secours vous ouvriront le compte ». La clé est mise de côté avec
  huit nouveaux codes de secours, qui s'affichent une fois. Elle ne devient active
  qu'après la preuve que vous les avez gardés : vous cliquez « Je les ai gardés »,
  les codes quittent l'écran, et vous retapez celui dont le serveur donne le
  numéro. Tant que ce n'est pas fait, votre compte ne change pas : rien n'est
  verrouillé, et « Annuler et recommencer » repart de zéro.
* **Dans les réglages**, un avertissement reste affiché tant que la clé est votre seul
  second facteur, avec le bouton « Ajouter une application à codes ».
* **Régénérer les codes de secours** (nouveau bouton, avec le nombre de codes
  restants) : demande votre code ou votre clé, émet huit codes en attente ; les
  anciens restent valables jusqu'à ce que vous ayez retapé l'un des nouveaux.
* **Écran de connexion** : le champ du code annonce « Code de vérification ou code de
  secours », et tout refus d'identifiants — quelle qu'en soit la cause — ajoute le même
  rappel (le code, un code de secours, ou la clé de sécurité). Le refus lui-même
  reste identique pour tous les comptes : rien ne dit ce que porte une adresse.
* Rien n'est affaibli : les codes restent gardés en empreintes seulement, le
  verrouillage après échecs est inchangé (une confirmation ne le remet pas à
  zéro), et un compte qui avait déjà une clé, ou une application à codes active,
  ajoute une clé comme avant (avec un facteur courant).
* Traductions fr, en, ar. Les autres langues retombent sur l'anglais.

## 2.31.0 — 26 octobre 2026

* **La clé de sécurité est vérifiée avant le mot de passe**, comme le code depuis
  la 2.30.0. Un compte protégé par une clé n'envoie plus son mot de passe à
  l'annuaire sans que la clé ait répondu. Ces comptes ne peuvent donc plus
  être verrouillés par un inconnu.
* À l'écran : le bouton « Utiliser une clé de sécurité » est présent dès
  l'ouverture de la page, partout où les clés sont allumées. Saisir l'adresse et
  le mot de passe, puis toucher la clé : la connexion part d'elle-même.
* La réponse est la même pour toutes les adresses, qu'elles aient une clé ou
  non, et rien n'est écrit tant qu'une clé n'a pas signé.

## 2.30.0 — 26 octobre 2026

* **Le code est vérifié avant le mot de passe.** Pour un compte dont le code
  d'authentification est activé, une connexion sans le bon code s'arrête dans le
  webmail : le mot de passe n'est pas envoyé à l'annuaire, aucun échec n'y est
  compté. Un inconnu qui connaît l'adresse ne peut donc plus verrouiller le
  compte, ni deviner son mot de passe par le webmail.
* Le refus est identique à celui d'un mot de passe faux, même message et même
  durée (réglage `precheck_delay`, 3 s par défaut) : rien ne dit qui a un second
  facteur.
* Un code faux ne compte plus dans le verrouillage du compte, sans quoi
  n'importe qui pourrait l'utiliser pour bloquer son propriétaire. La limite se
  fait par adresse IP (fail2ban).
* À l'écran : une connexion refusée avec le champ du code vide ajoute le rappel
  « saisissez aussi le code avec le mot de passe », pour tout compte.
* Clés de sécurité : rien ne change. Leur défi suit toujours un mot de passe
  juste.
* Ne couvre pas IMAP ni SMTP, qui interrogent l'annuaire directement.
