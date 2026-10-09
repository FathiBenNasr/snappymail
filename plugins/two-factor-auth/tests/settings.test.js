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
