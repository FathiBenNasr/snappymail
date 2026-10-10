'use strict';
// two-factor-auth 2.28.0 — the browser half of security keys, through the
// REAL files in a vm sandbox: js/TwoFactorWebAuthn.js, the login screen and
// the settings screen. navigator.credentials is a double that records what
// it was asked and answers like an authenticator would.
// Run: node --test plugins/two-factor-auth/tests/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const lire = f => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
const b64u = b => Buffer.from(b).toString('base64url');

// The window every file sees: atob/btoa, TextDecoder, a credentials double.
function fenetre(extra = {}) {
	const appels = [];
	const w = {
		atob: s => Buffer.from(s, 'base64').toString('binary'),
		btoa: s => Buffer.from(s, 'binary').toString('base64'),
		TextDecoder,
		isSecureContext: true,
		PublicKeyCredential: function () {},
		navigator: { credentials: {
			get: o => { appels.push(['get', o]); return w.reponse; },
			create: o => { appels.push(['create', o]); return w.reponse; }
		} },
		appels,
		...extra
	};
	w.window = w;
	vm.runInNewContext(lire('js/TwoFactorWebAuthn.js'), w);
	return w;
}
const credentielle = (champs) => ({
	id: 'aWQ', rawId: Uint8Array.from([105, 100]).buffer, type: 'public-key',
	response: Object.fromEntries(Object.entries(champs).map(([k, v]) => [k, Uint8Array.from(Buffer.from(v)).buffer]))
});
const refus = o => 'TwoFactorCodeRequired:' + b64u(JSON.stringify(o));
const OPTIONS = { challenge: b64u('le-défi-du-serveur-32-octets!!!!'), rpId: 'smail.tn', timeout: 300000, userVerification: 'discouraged',
	allowCredentials: [{ type: 'public-key', id: b64u('cle-1') }] };

test('base64url, both ways, on every byte value', () => {
	const w = fenetre();
	const octets = Uint8Array.from({ length: 256 }, (_, i) => i);
	const s = w.TwoFactorWebAuthn.b64u(octets.buffer);
	assert.strictEqual(s, b64u(octets));
	assert.deepStrictEqual(Buffer.from(w.TwoFactorWebAuthn.unb64u(s)), Buffer.from(octets));
});

test('the options appended to the refusal are read; the name alone means no key', () => {
	const w = fenetre();
	assert.deepStrictEqual(JSON.parse(JSON.stringify(w.TwoFactorWebAuthn.fromRefusal(refus(OPTIONS)))), OPTIONS);
	assert.strictEqual(w.TwoFactorWebAuthn.fromRefusal('TwoFactorCodeRequired'), null);
	assert.strictEqual(w.TwoFactorWebAuthn.fromRefusal('TwoFactorCodeRequired:%%%'), null);
	assert.strictEqual(w.TwoFactorWebAuthn.fromRefusal('TwoFactorCodeRequired:' + b64u('{"no":"challenge"}')), null);
});

test('request options become ArrayBuffers; the credential goes back as the JSON the server reads', async () => {
	const w = fenetre();
	w.reponse = Promise.resolve(credentielle({ clientDataJSON: '{"type":"webauthn.get"}', authenticatorData: 'AD', signature: 'SIG', userHandle: '' }));
	const json = JSON.parse(await w.TwoFactorWebAuthn.get(OPTIONS));
	const demande = w.appels[0][1].publicKey;
	assert.strictEqual(Buffer.from(demande.challenge).toString(), 'le-défi-du-serveur-32-octets!!!!');
	assert.strictEqual(Buffer.from(demande.allowCredentials[0].id).toString(), 'cle-1');
	assert.strictEqual(demande.rpId, 'smail.tn');
	assert.deepStrictEqual(json, { id: 'aWQ', rawId: 'aWQ', type: 'public-key',
		response: { clientDataJSON: b64u('{"type":"webauthn.get"}'), authenticatorData: b64u('AD'), signature: b64u('SIG') } });
});

test('creation options: the user handle and the excluded keys are decoded too', async () => {
	const w = fenetre();
	w.reponse = Promise.resolve(credentielle({ clientDataJSON: '{}', attestationObject: 'ATT' }));
	const json = JSON.parse(await w.TwoFactorWebAuthn.create({ rp: { id: 'smail.tn', name: 'Smail' }, user: { id: b64u('poignee'), name: 'a@smail.tn', displayName: 'a@smail.tn' },
		challenge: b64u('defi'), pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ type: 'public-key', id: b64u('vieille') }], attestation: 'none' }));
	const demande = w.appels[0][1].publicKey;
	assert.strictEqual(Buffer.from(demande.user.id).toString(), 'poignee');
	assert.strictEqual(Buffer.from(demande.excludeCredentials[0].id).toString(), 'vieille');
	assert.strictEqual(json.response.attestationObject, b64u('ATT'));
});

test('not supported without WebAuthn, nor outside a secure context', () => {
	assert.strictEqual(fenetre().TwoFactorWebAuthn.supported(), true);
	assert.strictEqual(fenetre({ PublicKeyCredential: undefined }).TwoFactorWebAuthn.supported(), false);
	assert.strictEqual(fenetre({ isSecureContext: false }).TwoFactorWebAuthn.supported(), false);
});

/* ---- the login screen ---- */

// A fake of the few DOM pieces the login script touches.
function ecranConnexion(extra = {}) {
	const w = fenetre(extra);
	const ecoute = {}, minuteries = [];
	const champs = {
		code: { value: '', focus() { this.focused = (this.focused || 0) + 1; }, dispatchEvent() {} },
		assertion: { value: '' },
		bouton: { hidden: true, ecouteurs: {}, querySelector: () => ({ addEventListener: (n, f) => { champs.bouton.clic = f; } }) },
		connexion: { clics: 0, click() { this.clics++; w.envoye.push({ code: champs.code.value, assertion: champs.assertion.value }); } }
	};
	w.envoye = [];
	const conteneur = { prepend() {}, append() {} };
	const vue = {
		viewModelTemplateID: 'Login', erreur: '',
		submitError(v) { this.erreur = v; }, submitErrorAdditional() {},
		viewModelDom: { querySelector: s => ({
			'#plugin-Login-BottomControlGroup': conteneur,
			'input[name=totp_code]': champs.code,
			'input[name=webauthn_assertion]': champs.assertion,
			'.twofactor-key': champs.bouton,
			'.buttonLogin': champs.connexion
		})[s] || null }
	};
	Object.assign(w, {
		addEventListener: (n, f) => { ecoute[n] = f; },
		setTimeout: f => minuteries.push(f),
		Element: { fromHTML: h => (h.includes('twofactor-key') ? champs.bouton : {}) },
		Event: function () {},
		document: { location: {} }
	});
	w.rl = { settings: { get: () => false }, i18n: k => '«' + k + '»' };
	vm.runInNewContext(lire('js/TwoFactorAuthLogin.js'), w);
	ecoute['rl-view-model']({ detail: vue });
	const repondre = d => { ecoute['sm-user-login-response']({ detail: d }); minuteries.splice(0).forEach(f => f()); };
	return { w, vue, champs, repondre };
}
const attendre = () => new Promise(r => setImmediate(r));

test('a key on the account: the button appears, the message names both ways', () => {
	const e = ecranConnexion();
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	assert.strictEqual(e.champs.bouton.hidden, false);
	assert.strictEqual(e.vue.erreur, '«PLUGIN_2FA/ERROR_CODE_OR_KEY_REQUIRED»');
	assert.strictEqual(e.champs.code.focused, 1);
});

test('TOTP only: no button, the message asks for the code as before', () => {
	const e = ecranConnexion();
	e.repondre({ error: 102, data: { messageAdditional: 'TwoFactorCodeRequired' } });
	assert.strictEqual(e.champs.bouton.hidden, true);
	assert.strictEqual(e.vue.erreur, '«PLUGIN_2FA/ERROR_CODE_REQUIRED»');
});

test('a browser without WebAuthn: no button even with a key', () => {
	const e = ecranConnexion({ PublicKeyCredential: undefined });
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	assert.strictEqual(e.champs.bouton.hidden, true);
});

test('the button: the key answers, the form goes again with the assertion in its hidden field', async () => {
	const e = ecranConnexion();
	e.w.reponse = Promise.resolve(credentielle({ clientDataJSON: '{}', authenticatorData: 'AD', signature: 'S' }));
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	e.champs.bouton.clic();
	await attendre();
	assert.strictEqual(e.w.appels[0][0], 'get');
	assert.strictEqual(e.w.envoye.length, 1);
	assert.strictEqual(JSON.parse(e.w.envoye[0].assertion).response.signature, b64u('S'));
	// Whatever the answer, the assertion is not sent twice.
	e.repondre({ error: 102, data: { messageAdditional: '' } });
	assert.strictEqual(e.champs.assertion.value, '');
});

test('the options are spent: a second press asks the server again (code field emptied), and the key follows', async () => {
	const e = ecranConnexion();
	e.w.reponse = Promise.resolve(credentielle({ clientDataJSON: '{}', authenticatorData: 'AD', signature: 'S' }));
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	e.champs.bouton.clic();
	await attendre();
	e.repondre({ error: 102, data: { messageAdditional: '' } });
	e.champs.code.value = '123';
	e.champs.bouton.clic();
	assert.deepStrictEqual(e.w.envoye[1], { code: '', assertion: '' });
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	await attendre();
	assert.strictEqual(e.w.appels.length, 2);
	assert.strictEqual(e.w.envoye.length, 3);
	assert.ok(e.w.envoye[2].assertion);
});

test('cancelled at the key: said, and nothing is sent', async () => {
	const e = ecranConnexion();
	e.w.reponse = Promise.reject(new Error('NotAllowedError'));
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	e.champs.bouton.clic();
	await attendre();
	assert.strictEqual(e.vue.erreur, '«PLUGIN_2FA/ERROR_PASSKEY_FAILED»');
	assert.strictEqual(e.w.envoye.length, 0);
});

test('signed in: the button goes away', () => {
	const e = ecranConnexion();
	e.repondre({ error: 102, data: { messageAdditional: refus(OPTIONS) } });
	e.repondre({ error: 0, data: { Result: {} } });
	assert.strictEqual(e.champs.bouton.hidden, true);
});

/* ---- the settings screen ---- */

function reglages(etat = { Auth: true }) {
	const w = fenetre();
	const appels = [], modales = [];
	const observable = v => { const o = n => (undefined === n ? v : (v = n)); return o; };
	let Vue = null;
	w.rl = {
		settings: { get: k => etat[k], set: (k, v) => { etat[k] = v; } },
		i18n: k => k,
		pluginRemoteRequest: (cb, action, prm) => appels.push({ cb, action, prm }),
		pluginPopupView: class { static showModal(a) { modales.push(a); } },
		addSettingsViewModel: c => { Vue = c; }
	};
	w.ko = { observable, computed: f => f, decorateCommands: () => {} };
	w.Intl = Intl;
	vm.runInNewContext(lire('js/TwoFactorAuthSettings.js'), w);
	return { v: new Vue(), w, appels, modales, etat };
}
const INFO = { User: 'a@smail.tn', IsSet: false, Enable: false, Tested: false, On: true, Enrolled: true, WebAuthn: true, MaxPasskeys: 2,
	Passkeys: [{ Ref: 'r1', Name: 'YubiKey', Created: 1760000000, LastUsed: 0 }] };

test('settings: the keys listed by name and date, never used said so, room for one more', () => {
	const r = reglages();
	r.v.onResult(0, { Result: INFO });
	const k = r.v.passkeys();
	assert.strictEqual(k.length, 1);
	assert.strictEqual(k[0].name(), 'YubiKey');
	assert.strictEqual(k[0].lastUsed, 'PLUGIN_2FA/PASSKEY_NEVER_USED');
	assert.match(k[0].created, /2025/);
	assert.deepStrictEqual([r.v.hasPasskeys(), r.v.canAddPasskey(), r.v.secondFactorOn()], [true, true, true]);
	r.v.onResult(0, { Result: { ...INFO, Passkeys: [INFO.Passkeys[0], INFO.Passkeys[0]] } });
	assert.strictEqual(r.v.canAddPasskey(), false);
});

test('settings: a first key — options, the authenticator, then the registration with its name; backup codes shown', async () => {
	const r = reglages();
	r.v.onResult(0, { Result: { ...INFO, On: false, Enrolled: false, Passkeys: [] } });
	r.v.newPasskeyName('Téléphone');
	r.w.reponse = Promise.resolve(credentielle({ clientDataJSON: '{}', attestationObject: 'ATT' }));
	r.v.addPasskey();
	assert.strictEqual(r.modales.length, 0, 'nothing to prove before the first factor');
	assert.strictEqual(r.appels[0].action, 'WebAuthnCreateOptions');
	r.appels[0].cb(0, { Result: { rp: { id: 'smail.tn' }, user: { id: b64u('u'), name: 'a', displayName: 'a' }, challenge: b64u('c'), pubKeyCredParams: [] } });
	await attendre();
	assert.strictEqual(r.appels[1].action, 'WebAuthnRegister');
	assert.strictEqual(r.appels[1].prm.Name, 'Téléphone');
	assert.strictEqual(JSON.parse(r.appels[1].prm.Credential).response.attestationObject, b64u('ATT'));
	r.appels[1].cb(0, { Result: { ...INFO, BackupCodes: '111111111 222222222' } });
	assert.strictEqual(r.v.viewBackupCodes(), '111111111  222222222');
	assert.strictEqual(r.v.newPasskeyName(), '');
});

test('settings: already protected, adding a key asks for a current factor, sent with the registration', async () => {
	const r = reglages();
	r.v.onResult(0, { Result: INFO });
	r.w.reponse = Promise.resolve(credentielle({ clientDataJSON: '{}', attestationObject: 'ATT' }));
	r.v.addPasskey();
	assert.strictEqual(r.appels.length, 0);
	assert.strictEqual(r.modales.length, 1);
	assert.strictEqual(r.modales[0][2], true, 'the popup offers the key');
	r.modales[0][1]('123456789', () => {});
	r.appels[0].cb(0, { Result: { rp: {}, user: { id: '' }, challenge: '', pubKeyCredParams: [] } });
	await attendre();
	assert.deepStrictEqual([r.appels[1].prm.Code, r.appels[1].prm.Assertion], ['123456789', undefined]);
});

test('settings: removing a key with the key itself sends { Assertion }, and the screen follows the answer', () => {
	const etat = { Auth: true, RequireTwoFactor: true, SetupTwoFactor: false };
	const r = reglages(etat);
	r.v.onResult(0, { Result: INFO });
	r.v.removePasskey(r.v.passkeys()[0]);
	let fini = null;
	r.modales[0][1]({ Assertion: '{"x":1}' }, (e, d) => { fini = d.Result; });
	assert.deepStrictEqual(JSON.parse(JSON.stringify(r.appels[0].prm)), { Ref: 'r1', Code: '', Assertion: '{"x":1}' });
	r.appels[0].cb(0, { Result: { ...INFO, On: false, Enrolled: false, Passkeys: [] } });
	assert.deepStrictEqual([fini, r.v.hasPasskeys(), etat.SetupTwoFactor], [true, false, true]);
});

test('settings: renamed by reference, with the draft', () => {
	const r = reglages();
	r.v.onResult(0, { Result: INFO });
	const k = r.v.passkeys()[0];
	r.v.renamePasskey(k);
	k.draft('Clé du bureau');
	r.v.savePasskey(k);
	assert.deepStrictEqual(JSON.parse(JSON.stringify([r.appels[0].action, r.appels[0].prm])), ['WebAuthnRename', { Ref: 'r1', Name: 'Clé du bureau' }]);
});

test('settings: before login (Auth not true), nothing is asked of the server', () => {
	const r = reglages({ Auth: undefined });
	r.v.onBuild();
	r.v.addPasskey();
	assert.strictEqual(r.appels.length, 0);
});

/* ---- the three catalogues ---- */

test('every PLUGIN_2FA key the screens use is in en and fr; every 2.28.0 key in ar too', () => {
	const ini = l => Object.fromEntries(lire('langs/' + l + '.ini').split('\n').map(x => /^(\w+)\s*=/.exec(x)).filter(Boolean).map(m => [m[1], 1]));
	const utilisees = new Set();
	for (const f of ['js/TwoFactorAuthLogin.js', 'js/TwoFactorAuthSettings.js', 'templates/TwoFactorAuthSettings.html', 'templates/PopupsTwoFactorAuthTest.html']) {
		// A name built at run time (TWO_FACTOR_SECRET_ + …) ends with '_': not a key.
		for (const m of lire(f).matchAll(/PLUGIN_2FA\/(\w+)/g)) m[1].endsWith('_') || utilisees.add(m[1]);
	}
	const en = ini('en'), fr = ini('fr'), ar = ini('ar');
	for (const k of utilisees) {
		assert.ok(en[k], 'en: ' + k);
		assert.ok(fr[k], 'fr: ' + k);
	}
	for (const k of Object.keys(en).filter(k => /PASSKEY|KEY_REQUIRED/.test(k))) assert.ok(ar[k], 'ar: ' + k);
});
