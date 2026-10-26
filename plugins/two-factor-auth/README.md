# Two Factor Authentication (two-factor-auth)

![Settings: a security key registered, backup codes shown once](docs/captures/cle-1-reglages.png)
![Login: the password was right, the key is offered](docs/captures/cle-2-connexion.png)
![Login without the code: refused like a wrong password, with a reminder shown to everyone](docs/captures/avant-1-rappel.png)

A second factor for SnappyMail logins: a **TOTP** code (any authenticator app),
**backup codes**, and since 2.28.0 **security keys and passkeys (WebAuthn)**.
Captures and how they are made: [`docs/captures/`](docs/captures/README.md).

## Security keys are a second factor, not a password replacement

SnappyMail opens the mailbox over IMAP **with the person's password**. A
passkey proves who is at the keyboard; it does not give the server that
password. Logging in with a passkey alone would need the server to keep every
password, or a master credential able to open any mailbox — both refused by
design. So the password comes first, then the code or the key.

## The code is checked before the password (2.30.0)

Every wrong password the webmail sends to IMAP is a failure counted by the
directory's password policy, which slows and then locks the account: whoever
knows an address could lock its owner out. For an account whose TOTP is on,
the code is now judged **before** the password leaves the webmail
(`filter.account`, right after `login.credentials`). Without the right code,
nothing reaches IMAP or the directory, nothing is counted, and the password
cannot be guessed through the webmail.

What this would open, and how it is closed:

* **Who has a second factor must not show.** The refusal is the core's own for
  a wrong password (`AuthError`, no additional message, the core's auth-log
  line read by fail2ban) and lasts as long (`precheck_delay`, 3 s — Cyrus'
  `failedloginpause`). The reminder "type the code with your password" is
  decided by the browser from the empty field alone, for every account.
* **No lockout anyone can trigger.** A wrong code before the password is not
  counted toward the record's lockout, and is judged without taking the
  record's lock or writing it. The limit is per IP (fail2ban). Each right code
  lets one password through once (its time step is spent): guessing the
  password now costs some 330 000 guessed codes per try.
* **Security keys** too, since 2.31.0. The login screen offers "Use a
  security key" from the start, wherever keys are on, to every visitor. The
  button asks `WebAuthnLoginOptions` for the typed address. The answer is the
  same for every address: an address without a key gets decoy credential ids,
  derived from it, stable, and 64 bytes long. The challenge is **stateless**
  (random bytes, an expiry, and a MAC over the address and the browser's
  connection token): nothing is written until a key signs it, so a flood of
  requests cannot push the owner's challenges out. The assertion is then
  judged before the password, written only on success, and its challenge is
  marked spent, which stops the replay of a passkey that has no counter.
* **Not covered:** IMAP and SMTP clients, which reach the directory directly
  (app passwords and the directory's slowdown guard them).

Proved on banc-smail:
* `BANC=avant`: three refusals, 0 failures counted by the directory; the
  control (right code, wrong password) counts exactly one;
* `BANC=cle`: two logins without a factor, 0 failures counted, then the key
  logs in.

## Settings (admin panel → plugin)

| Setting | Default | |
|---|---|---|
| `force_two_factor_auth`, `force_two_factor_domains` | off, empty | everyone / these domains must set up a second factor (held by the server since 2.27.0) |
| `precheck_delay` | 3 | seconds a refusal before the password waits (0–10), as long as a wrong password |
| `webauthn_enabled` | off | security keys and passkeys |
| `webauthn_origins` | empty | the webmail origins, e.g. `https://webmail.example.com`; empty = keys off. The Host header is never trusted |
| `webauthn_rp_id` | host of the first origin | the domain keys are bound to; changing it voids every key |
| `webauthn_require_uv` | off | require a PIN or biometrics on the key |
| `webauthn_max_passkeys` | 10 | per account (1–50) |
| `webauthn_challenge_ttl` | 300 | seconds (30–3600); each challenge is used once |
| `webauthn_counter_regression` | refuse | `refuse` or `warn` when a key's signature counter goes back |

Verified on the server, without any third-party library
(`providers/webauthn.php`): ES256, RS256 (2048–4096 bits), EdDSA (Ed25519, with
sodium); attestation `none` and `packed` (the chain is not trusted, the
statement must verify); strict, bounded CBOR. Keys are stored in the account's
record, sealed with a key derived from `APP_SALT`.

## Tests

    php plugins/two-factor-auth/tests/WebAuthnTest.php   # the verifier, real authenticator vectors
    php plugins/two-factor-auth/tests/ActionsTest.php    # the plugin's actions
    php plugins/two-factor-auth/tests/RecordTest.php     # the stored record
    node --test plugins/two-factor-auth/tests/*.test.js  # the browser code, in node:vm
    BANC=cle sh plugins/two-factor-auth/tests/browser/preparer.sh   # banc-smail, CDP virtual authenticator
    BANC=avant sh plugins/two-factor-auth/tests/browser/preparer.sh # banc-smail, the directory's failure count
