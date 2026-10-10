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
		Element: { fromHTML: () => ({}) },
		document: { location: {} },
		window: {}
	};
	bac.window.rl = { settings: { get: () => false }, i18n: k => '«' + k + '»' };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthLogin.js'), 'utf8'), bac);
	ecoute['rl-view-model']({ detail: vue });
	const repondre = d => { ecoute['sm-user-login-response']({ detail: d }); minuteries.splice(0).forEach(f => f()); };
	return { vue, repondre, focalise: () => focalise };
}

test('code absent : l\'écran demande le code et y place le curseur', () => {
	const c = charger();
	c.repondre({ error: 102, data: { messageAdditional: 'TwoFactorCodeRequired' } });
	assert.strictEqual(c.vue.erreur, '«PLUGIN_2FA/ERROR_CODE_REQUIRED»');
	assert.strictEqual(c.vue.complement, '');
	assert.strictEqual(c.focalise(), 1);
});

test('mot de passe refusé : le message du cœur reste', () => {
	const c = charger();
	c.repondre({ error: 102, data: { messageAdditional: '' } });
	assert.strictEqual(c.vue.erreur, '');
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
