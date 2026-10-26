# two-factor-auth — journal des versions

Les versions antérieures à 2.30.0 sont décrites, avec leurs mesures, dans
[`TODO.md`](TODO.md).

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
