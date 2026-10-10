#!/bin/sh
# two-factor-auth — "enforce 2-Step Verification" held by the server, on
# banc-smail ONLY (never fastmail.convergent.tn nor webmail.smail.tn).
#
#     sh plugins/two-factor-auth/tests/browser/preparer.sh          # verdict
#     MESURE=1 sh plugins/two-factor-auth/tests/browser/preparer.sh # only log the actions called
#     CAPTURES=/dir sh ...                                          # screenshots of the three screens
#
# 1. puts THIS plugin in the bench (the bench's own copy is saved and put back),
# 2. sets force_two_factor_domains = smail.tn in the BENCH's plugin config only,
# 3. empties the bench cache (files, as on smail.tn) so the new JS is served,
# 4. creates an ephemeral essai.* account (password from the environment,
#    never written), runs forcer.js in puppeteer-test, deletes the account.
#
# Prerequisites: the banc-smail and puppeteer-test containers are up
# (tools/banc-conteneurs/README.md). Runs as root on the host.
set -eu
ICI=$(cd "$(dirname "$0")" && pwd)
GREFFON=$(cd "$ICI/../.." && pwd)
COMPTES=${COMPTES:-/root/Development/SnappyMail/business/smail-tn/tests/browser/comptes_essai.php}
RACINE=/opt/docker/SnappyMail-banc/smail
D=$RACINE/htdocs/data/_data_/_default_
CONF=$D/configs/plugin-two-factor-auth.json
SAUVE=$RACINE/sauvegarde-2fa-$$
[ -d "$D/plugins" ] || { echo "pas de banc-smail sous $RACINE" >&2; exit 2; }
[ -f "$GREFFON/index.php" ] || { echo "pas de greffon dans $GREFFON" >&2; exit 2; }

vider_cache() { find "$D/cache" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +; }

# The bench's own copy and configuration, put back at the end whatever happens.
mkdir -m 700 "$SAUVE"
cp -a "$D/plugins/two-factor-auth" "$SAUVE/plugin"
[ -f "$CONF" ] && cp -a "$CONF" "$SAUVE/conf.json"
A=essai.tfa$(date +%H%M%S)
MDP="Pz$(openssl rand -base64 18 | tr -d '/+=')#7"
export MDP
menage() {
	sudo -u apache php -- supprimer "$A" < "$COMPTES" >/dev/null || echo "⚠️ suppression de $A incomplète"
	rm -rf "$D/storage/smail.tn/$A"
	rm -rf "$D/plugins/two-factor-auth"
	cp -a "$SAUVE/plugin" "$D/plugins/two-factor-auth"
	if [ -f "$SAUVE/conf.json" ]; then cp -a "$SAUVE/conf.json" "$CONF"; else rm -f "$CONF"; fi
	rm -rf "$SAUVE"
	vider_cache
	echo "banc remis : greffon et configuration d'origine"
}
trap menage EXIT

rm -rf "$D/plugins/two-factor-auth"
cp -r "$GREFFON" "$D/plugins/two-factor-auth"
rm -rf "$D/plugins/two-factor-auth/tests"
python3 - "$CONF" <<'PY'
import json, os, sys
f = sys.argv[1]
c = json.load(open(f)) if os.path.exists(f) else {}
c.setdefault('plugin', {})['force_two_factor_domains'] = 'smail.tn'
json.dump(c, open(f, 'w'), indent=4)
PY
chown -R 33:33 "$D/plugins/two-factor-auth" "$CONF"
chmod -R u+rwX,g-rwx,o-rwx "$D/plugins/two-factor-auth" "$CONF"
vider_cache
echo "greffon two-factor-auth <- $GREFFON ($(sed -n "s/.*VERSION *= *'\([^']*\)'.*/\1/p" "$GREFFON/index.php"))"

sudo -E -u apache php -- creer "$A" < "$COMPTES" | head -1
podman exec puppeteer-test mkdir -p /essai/two-factor-auth
podman cp "$ICI/forcer.js" puppeteer-test:/essai/two-factor-auth/forcer.js
[ -n "${CAPTURES:-}" ] && podman exec puppeteer-test mkdir -p /essai/two-factor-auth/captures
A="$A@smail.tn" MESURE=${MESURE:-} podman exec -e MDP -e A -e MESURE \
	${CAPTURES:+-e CAPTURES=/essai/two-factor-auth/captures} \
	puppeteer-test node /essai/two-factor-auth/forcer.js || STATUT=$?
if [ -n "${CAPTURES:-}" ]; then
	mkdir -p "$CAPTURES"
	podman cp puppeteer-test:/essai/two-factor-auth/captures/. "$CAPTURES/"
fi
exit ${STATUT:-0}
