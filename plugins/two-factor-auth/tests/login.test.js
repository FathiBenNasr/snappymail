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
