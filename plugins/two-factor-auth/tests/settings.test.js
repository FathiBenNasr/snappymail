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

// 2.32.0: a key as the only second factor, and the proof that the backup codes are kept.
const info = (o = {}) => Object.assign({ User: 'a@smail.tn', IsSet: false, Enable: false, Tested: false, On: false, Enrolled: false,
	OnlyKey: false, Pending: false, PendingAsk: 0, PendingKey: false, BackupLeft: 0, WebAuthn: true, MaxPasskeys: 10, Passkeys: [] }, o);
const reglagesAuth = { Auth: true };

test('2.32.0: l\'avertissement suit la réponse du serveur : clé seule, puis plus rien', () => {
	const { v } = vueAvecServeur(reglagesAuth);
	v.applyInfo(info({ On: true, Enrolled: true, OnlyKey: true, BackupLeft: 8, Passkeys: [{ Ref: 'r', Name: 'k', Created: 0, LastUsed: 0 }] }));
	assert.strictEqual(v.onlyKey(), true);
	assert.strictEqual(v.backupLeft(), 8);
	v.applyInfo(info({ On: true, Enrolled: true, Enable: true, OnlyKey: false, Passkeys: [{ Ref: 'r', Name: 'k', Created: 0, LastUsed: 0 }] }));
	assert.strictEqual(v.onlyKey(), false);
});

test('2.32.0: codes en attente : le rang demandé est annoncé, jamais les codes', () => {
	const { v } = vueAvecServeur(reglagesAuth);
	v.applyInfo(info({ Pending: true, PendingKey: true, PendingAsk: 5 }));
	assert.deepStrictEqual([v.pending(), v.pendingKey(), v.pendingAsk(), v.confirmLabel()], [true, true, 5, 'PLUGIN_2FA/LABEL_CONFIRM_CODE_N']);
	v.confirmCode('123');
	v.applyInfo(info());
	assert.deepStrictEqual([v.pending(), v.confirmCode()], [false, '']);
});

test('2.32.0: « je les ai gardés » retire les codes de l\'écran', () => {
	const { v } = vueAvecServeur(reglagesAuth);
	v.viewBackupCodes('111111111  222222222');
	v.savedCodes();
	assert.strictEqual(v.viewBackupCodes(), '');
});

test('2.32.0: la preuve part au serveur, nettoyée ; vide, elle ne part pas', () => {
	const { v, appels } = vueAvecServeur(reglagesAuth);
	v.confirmCodes();
	assert.strictEqual(appels.length, 0);
	v.confirmCode('  123456789 ');
	v.confirmCodes();
	assert.deepStrictEqual([appels[0].action, JSON.stringify(appels[0].prm)], ['ConfirmBackupCodes', '{"Code":"123456789"}']);
	v.confirmCodes();
	assert.strictEqual(appels.length, 1, 'une seule requête à la fois');
	appels[0].cb(0, { Result: info({ On: true, Enrolled: true, OnlyKey: true }) });
	assert.deepStrictEqual([v.onlyKey(), v.confirmCode(), v.confirmError()], [true, '', '']);
});

test('2.32.0: preuve refusée : message, et l\'état est relu (trop d\'essais jettent les codes)', () => {
	const { v, appels } = vueAvecServeur(reglagesAuth);
	v.applyInfo(info({ Pending: true, PendingKey: true, PendingAsk: 2 }));
	v.confirmCode('000000000');
	v.confirmCodes();
	appels[0].cb(0, { Result: false });
	assert.strictEqual(v.confirmError(), 'PLUGIN_2FA/ERROR_CODE_NOT_CONFIRMED');
	assert.strictEqual(appels[1].action, 'GetTwoFactorInfo');
	appels[1].cb(0, { Result: info() });
	assert.strictEqual(v.pending(), false);
});

test('2.32.0: annuler demande au serveur de jeter ce qui attend', () => {
	const { v, appels } = vueAvecServeur(reglagesAuth);
	v.viewBackupCodes('x');
	v.cancelPending();
	assert.deepStrictEqual([appels[0].action, v.viewBackupCodes()], ['CancelPendingCodes', '']);
});

test('2.32.0: régénérer passe par un facteur courant, montre les codes une fois', () => {
	const { v, appels } = vueAvecServeur(reglagesAuth);
	let prouve = null;
	v.prove = action => { prouve = action; };
	v.regenerateCodes();
	let fini = null;
	prouve({ Code: '654321' }, (e, d) => { fini = d; });
	assert.deepStrictEqual([appels[0].action, JSON.stringify(appels[0].prm)], ['RegenerateBackupCodes', '{"Code":"654321"}']);
	appels[0].cb(0, { Result: info({ On: true, Pending: true, PendingAsk: 3, BackupCodes: '111111111 222222222' }) });
	assert.deepStrictEqual([v.viewBackupCodes(), fini.Result, v.pendingAsk()], ['111111111  222222222', true, 3]);
});

test('2.32.0: devant l\'écran de connexion (pas authentifié), rien n\'est demandé', () => {
	const { v, appels } = vueAvecServeur({ Auth: false });
	v.confirmCode('123456789');
	v.confirmCodes();
	v.regenerateCodes();
	assert.strictEqual(appels.length, 0);
});
