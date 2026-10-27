'use strict';
// The real TwoFactorAuthLogin.js in a vm sandbox: the missing code is named.
// Run: node --test plugins/two-factor-auth/tests/
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

function charger() {
	const ecoute = {}, minuteries = [];
	let focalise = 0;
	const champ = { focus: () => ++focalise };
	const vue = {
		viewModelTemplateID: 'Login',
		viewModelDom: { querySelector: s => ('input[name=totp_code]' === s ? champ : null) },
		erreur: '', complement: 'x',
		submitError(v) { this.erreur = v; }, submitErrorAdditional(v) { this.complement = v; }
	};
	const bac = {
		addEventListener: (n, f) => { ecoute[n] = f; },
		setTimeout: f => minuteries.push(f),
		queueMicrotask: f => minuteries.push(f),
		Element: { fromHTML: () => ({}) },
		document: { location: {} },
		window: {}
	};
	bac.window.rl = { settings: { get: () => false }, i18n: k => '«' + k + '»' };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthLogin.js'), 'utf8'), bac);
	ecoute['rl-view-model']({ detail: vue });
	const repondre = d => { ecoute['sm-user-login-response']({ detail: d }); minuteries.splice(0).forEach(f => f()); };
	return { vue, champ, repondre, focalise: () => focalise };
}

test('code absent : l\'écran demande le code et y place le curseur', () => {
	const c = charger();
	c.repondre({ error: 102, data: { messageAdditional: 'TwoFactorCodeRequired' } });
	assert.strictEqual(c.vue.erreur, '«PLUGIN_2FA/ERROR_CODE_REQUIRED»');
	assert.strictEqual(c.vue.complement, '');
	assert.strictEqual(c.focalise(), 1);
});

// 2.32.0: the reminder follows EVERY refusal of the credentials — the same
// text for any account, a wrong code or an empty one — and names the backup code.
test('mot de passe refusé, code saisi : le même rappel, pour tout compte', () => {
	const c = charger();
	c.champ.value = '123456';
	c.repondre({ error: 102, data: { messageAdditional: '' } });
	assert.strictEqual(c.vue.erreur, '');
	assert.strictEqual(c.vue.complement, '«PLUGIN_2FA/HINT_CODE_WITH_PASSWORD»');
});

test('refus avec le champ du code vide : le même rappel (rien ne distingue les causes)', () => {
	const c = charger();
	c.champ.value = '  ';
	c.repondre({ error: 102, data: { messageAdditional: '' } });
	assert.strictEqual(c.vue.erreur, '');
	assert.strictEqual(c.vue.complement, '«PLUGIN_2FA/HINT_CODE_WITH_PASSWORD»');
});

test('refus : le rappel est identique avec champ vide, plein, ou sans champ', () => {
	const textes = new Set();
	for (const valeur of [undefined, '', '123456', '000000000']) {
		const c = charger();
		valeur !== undefined && (c.champ.value = valeur);
		c.repondre({ error: 102, data: { messageAdditional: '' } });
		textes.add(c.vue.erreur + '|' + c.vue.complement);
	}
	assert.strictEqual(textes.size, 1);
});

test('autre erreur que l\'authentification (serveur injoignable) : pas de rappel', () => {
	const c = charger();
	c.repondre({ error: 104, data: { messageAdditional: '' } });
	assert.strictEqual(c.vue.complement, 'x');
});

test('connexion réussie avec le champ vide : pas de rappel', () => {
	const c = charger();
	c.repondre({ error: 0, data: { Result: {} } });
	assert.strictEqual(c.vue.complement, 'x');
});

test('connexion réussie : rien n\'est touché', () => {
	const c = charger();
	c.repondre({ error: 0, data: { Result: {} } });
	assert.strictEqual(c.vue.erreur, '');
});

// 2.27.0: once enrolled, leaving the settings reloads the application once —
// the server had refused what the mailbox loads at boot.
function ecran(reglages) {
	const ecoute = {};
	let recharge = 0;
	const bac = {
		addEventListener: (n, f) => { ecoute[n] = f; },
		setTimeout: f => f(),
		Element: { fromHTML: () => ({}) },
		document: { location: { hash: '', reload: () => ++recharge } },
		window: {}
	};
	bac.window.rl = { settings: { get: k => reglages[k] }, i18n: k => k };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthLogin.js'), 'utf8'), bac);
	const aller = cible => { let annule = false; ecoute['sm-show-screen']({ detail: cible, preventDefault: () => { annule = true; } }); return annule; };
	return { aller, recharge: () => recharge, location: bac.document.location };
}

test('2.27.0: forced, the mailbox is refused and the settings screen is opened', () => {
	const e = ecran({ SetupTwoFactor: true });
	assert.strictEqual(e.aller('mailbox/INBOX'), true);
	assert.strictEqual(e.location.hash, '#/settings/two-factor-auth');
	assert.strictEqual(e.aller('settings/two-factor-auth'), false);
	assert.strictEqual(e.recharge(), 0);
});

test('2.27.0: enrolled in this page, leaving the settings reloads; staying in them does not', () => {
	const reglages = { SetupTwoFactor: true };
	const e = ecran(reglages);
	e.aller('mailbox/INBOX');
	reglages.SetupTwoFactor = false;
	assert.strictEqual(e.aller('settings/general'), false);
	assert.strictEqual(e.recharge(), 0);
	assert.strictEqual(e.aller('mailbox/INBOX'), true);
	assert.strictEqual(e.recharge(), 1);
});

test('2.27.0: never forced in this page, nothing is reloaded nor refused', () => {
	const e = ecran({ SetupTwoFactor: false });
	assert.strictEqual(e.aller('mailbox/INBOX'), false);
	assert.strictEqual(e.aller('settings/general'), false);
	assert.strictEqual(e.recharge(), 0);
});


// 2.29.0: the refusal carries the key's request options. The core writes it
// under the error in the same task as the event; it must be gone before the
// browser paints — that is, before the end of the microtask checkpoint.
test('le défi n\'est jamais peint : effacé avant la fin de la tâche', async () => {
	const ecoute = {};
	const vue = {
		viewModelTemplateID: 'Login',
		viewModelDom: { querySelector: () => null },
		erreur: '', complement: '',
		submitError(v) { this.erreur = v; }, submitErrorAdditional(v) { this.complement = v; }
	};
	let peint = null;
	const bac = {
		addEventListener: (n, f) => { ecoute[n] = f; },
		setTimeout,
		queueMicrotask,
		Element: { fromHTML: () => ({}) },
		document: { location: {} },
		window: {}
	};
	bac.window.rl = { settings: { get: () => false }, i18n: k => k };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthLogin.js'), 'utf8'), bac);
	ecoute['rl-view-model']({ detail: vue });
	const refus = 'TwoFactorCodeRequired:eyJjaGFsbGVuZ2UiOiJhYmMifQ';
	// What Login.js does, in one task: the event, then its own two setters.
	ecoute['sm-user-login-response']({ detail: { error: 102, data: { messageAdditional: refus } } });
	vue.submitError('Authentication failed');
	vue.submitErrorAdditional(refus);
	// A browser may paint once the task and its microtasks are done, before
	// the next task. So the text must be gone at the end of this task's
	// microtask checkpoint — read here, with a microtask queued after the
	// plugin's; a setTimeout would come too late, whatever its delay.
	await Promise.resolve();
	peint = vue.complement;
	assert.strictEqual(peint, '', 'le défi aurait été peint');
	assert.strictEqual(vue.erreur, 'PLUGIN_2FA/ERROR_CODE_REQUIRED');
});

// 2.32.0: with the keys on, the login screen offers the key to every visitor,
// and the refusal hint names it too — the same for all accounts.
function avecCles(cles) {
	const ecoute = {}, files = [];
	const html = [];
	const conteneur = { prepend: e => html.push(e), append: e => html.push(e) };
	const vue = {
		viewModelTemplateID: 'Login',
		viewModelDom: { querySelector: s => ('#plugin-Login-BottomControlGroup' === s ? conteneur : null) },
		erreur: '', complement: '',
		submitError(v) { this.erreur = v; }, submitErrorAdditional(v) { this.complement = v; }
	};
	const bac = {
		addEventListener: (n, f) => { ecoute[n] = f; },
		setTimeout: f => files.push(f), queueMicrotask: f => files.push(f),
		Element: { fromHTML: h => ({ h, querySelector: () => null }) },
		document: { location: {} },
		window: { TwoFactorWebAuthn: { supported: () => true, fromRefusal: () => null } }
	};
	bac.window.rl = { settings: { get: k => ('TwoFactorKeyLogin' === k ? cles : false) }, i18n: k => '«' + k + '»' };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthLogin.js'), 'utf8'), bac);
	ecoute['rl-view-model']({ detail: vue });
	return { vue, html, repondre: d => { ecoute['sm-user-login-response']({ detail: d }); files.splice(0).forEach(f => f()); } };
}

test('2.32.0: le champ du code annonce « ou un code de secours », pour tout visiteur', () => {
	for (const cles of [true, false]) {
		const e = avecCles(cles);
		assert.ok(e.html.some(x => x.h.includes('PLUGIN_2FA/PLACEHOLDER_LOGIN_CODE')), 'placeholder');
		assert.ok(!e.html.some(x => x.h.includes('LABEL_TWO_FACTOR_CODE')));
	}
});

test('2.32.0: clés allumées : le rappel de refus cite la clé ; éteintes : il ne la cite pas', () => {
	const a = avecCles(true); a.repondre({ error: 102, data: { messageAdditional: '' } });
	assert.strictEqual(a.vue.complement, '«PLUGIN_2FA/HINT_CODE_OR_KEY_WITH_PASSWORD»');
	const b = avecCles(false); b.repondre({ error: 102, data: { messageAdditional: '' } });
	assert.strictEqual(b.vue.complement, '«PLUGIN_2FA/HINT_CODE_WITH_PASSWORD»');
});

test('2.32.0: le bouton de la clé est dans la page pour tous, avec les clés allumées', () => {
	const e = avecCles(true);
	assert.ok(e.html.some(x => x.h.includes('twofactor-key')));
});
