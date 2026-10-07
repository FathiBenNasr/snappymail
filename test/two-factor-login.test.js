'use strict';
// Run with: node --test test/two-factor-login.test.js
// The real plugins/two-factor-auth/js/TwoFactorAuthLogin.js, and its .min.js, in a
// vm sandbox: a missing code is named on the login screen.
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

function load(file) {
	const listeners = {}, timers = [];
	let focused = 0;
	const field = { focus: () => ++focused };
	const view = {
		viewModelTemplateID: 'Login',
		viewModelDom: { querySelector: s => ('input[name=totp_code]' === s ? field : null) },
		error: '', additional: 'x',
		submitError(v) { this.error = v; }, submitErrorAdditional(v) { this.additional = v; }
	};
	const sandbox = {
		addEventListener: (n, f) => { listeners[n] = f; },
		setTimeout: f => timers.push(f),
		Element: { fromHTML: () => ({}) },
		document: { location: {} },
		window: {}
	};
	sandbox.window.rl = { settings: { get: () => false }, i18n: k => '[' + k + ']' };
	vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../plugins/two-factor-auth/js', file), 'utf8'), sandbox);
	listeners['rl-view-model']({ detail: view });
	const respond = d => { listeners['sm-user-login-response']({ detail: d }); timers.splice(0).forEach(f => f()); };
	return { view, respond, focused: () => focused };
}

for (const file of ['TwoFactorAuthLogin.js', 'TwoFactorAuthLogin.min.js']) {
	test(`${file}: missing code, the screen asks for it and focuses the field`, () => {
		const c = load(file);
		c.respond({ error: 102, data: { messageAdditional: 'TwoFactorCodeRequired' } });
		assert.strictEqual(c.view.error, '[PLUGIN_2FA/ERROR_CODE_REQUIRED]');
		assert.strictEqual(c.view.additional, '');
		assert.strictEqual(c.focused(), 1);
	});

	test(`${file}: wrong password or code, the core message stays`, () => {
		const c = load(file);
		c.respond({ error: 102, data: { messageAdditional: '' } });
		assert.strictEqual(c.view.error, '');
		assert.strictEqual(c.view.additional, 'x');
	});

	test(`${file}: successful login, nothing is touched`, () => {
		const c = load(file);
		c.respond({ error: 0, data: { Result: {} } });
		assert.strictEqual(c.view.error, '');
	});
}

test('the code-required message exists in langs/en.ini', () => {
	const ini = fs.readFileSync(path.join(__dirname, '../plugins/two-factor-auth/langs/en.ini'), 'utf8');
	assert.match(ini, /^ERROR_CODE_REQUIRED = "[^"]+"$/m);
});
