# two-factor-auth — journal des versions

Les versions antérieures à 2.30.0 sont décrites, avec leurs mesures, dans
[`TODO.md`](TODO.md).

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
