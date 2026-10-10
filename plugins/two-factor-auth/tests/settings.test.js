'use strict';
// The real TwoFactorAuthSettings.js in a vm sandbox: the app-password note (S-09).
// Run: node --test plugins/two-factor-auth/tests/
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

function vue(reglages) {
	const observable = v => { const o = n => (undefined === n ? v : (v = n)); return o; };
	let Vue = null;
	const rl = {
		settings: { get: k => reglages[k], set: (k, v) => { reglages[k] = v; } },
		i18n: k => k,
		pluginRemoteRequest: () => {},
		pluginPopupView: class {},
		addSettingsViewModel: c => { Vue = c; }
	};
	const ko = { observable, computed: f => f, decorateCommands: () => {} };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthSettings.js'), 'utf8'),
		{ window: { rl }, ko });
	return new Vue();
}

test('S-09: no app-password note when the server does not enforce app passwords', () => {
	assert.strictEqual(vue({}).appPasswordsNote(), false);
	assert.strictEqual(vue({ TwoFactorAppPasswords: false }).appPasswordsNote(), false);
});

test('S-09: the note is shown where it is enforced, and re-read when the screen is shown', () => {
	const reglages = { TwoFactorAppPasswords: true };
	const v = vue(reglages);
	assert.strictEqual(v.appPasswordsNote(), true);
	reglages.TwoFactorAppPasswords = false;
	v.onShow();
	assert.strictEqual(v.appPasswordsNote(), false);
});

// 2.27.0: the server refuses everything until the second factor is on, so the
// screen's idea of "forced" must follow what the server answered.
function vueAvecServeur(reglages) {
	const appels = [];
	const observable = v => { const o = n => (undefined === n ? v : (v = n)); return o; };
	let Vue = null;
	const rl = {
		settings: { get: k => reglages[k], set: (k, v) => { reglages[k] = v; } },
		i18n: k => k,
		pluginRemoteRequest: (cb, action, prm) => appels.push({ cb, action, prm }),
		pluginPopupView: class {},
		addSettingsViewModel: c => { Vue = c; }
	};
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../js/TwoFactorAuthSettings.js'), 'utf8'),
		{ window: { rl }, ko: { observable, computed: f => f, decorateCommands: () => {} } });
	return { v: new Vue(), appels };
}

test('2.27.0: enabled for real, the screen stops forcing', () => {
	const reglages = { RequireTwoFactor: true, SetupTwoFactor: true };
	const { v, appels } = vueAvecServeur(reglages);
	v.twoFactorTested(true);
	v.viewEnable.write(true);
	assert.strictEqual(appels[0].action, 'EnableTwoFactor');
	appels[0].cb(0, { Result: true });
	assert.strictEqual(reglages.SetupTwoFactor, false);
});

test('2.27.0: a refusal without an error code (Result false) is not "enabled"', () => {
	const reglages = { RequireTwoFactor: true, SetupTwoFactor: true };
	const { v, appels } = vueAvecServeur(reglages);
	v.twoFactorTested(true);
	v.viewEnable.write(true);
	appels[0].cb(0, { Result: false });
	assert.strictEqual(reglages.SetupTwoFactor, true);
	assert.strictEqual(v.viewEnable_(), false);
});

test('2.27.0: cleared again, the screen forces again; not required, nothing is forced', () => {
	const reglages = { RequireTwoFactor: true, SetupTwoFactor: false };
	const { v, appels } = vueAvecServeur(reglages);
	v.clearTwoFactor();
	assert.strictEqual(appels[0].action, 'ClearTwoFactorInfo');
	appels[0].cb(0, { Result: { User: 'a@smail.tn', IsSet: false, Enable: false, Tested: false } });
	assert.strictEqual(reglages.SetupTwoFactor, true);

	const libre = { RequireTwoFactor: false, SetupTwoFactor: false };
	const b = vueAvecServeur(libre);
	b.v.clearTwoFactor();
	b.appels[0].cb(0, { Result: { User: 'a@smail.tn', IsSet: false, Enable: false, Tested: false } });
	assert.strictEqual(libre.SetupTwoFactor, false);
});
