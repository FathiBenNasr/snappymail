/*
import { trigger as translatorTrigger } from 'Common/Translator';
*/

(rl => { if (rl) {

const
	pString = value => null != value ? '' + value : '',

	// Logged in (AppData.Auth strictly true): nothing is asked of the server before.
	authentifie = () => {
		try {
			return true === (window.rl && rl.settings && rl.settings.get('Auth'));
		} catch (e) {
			return false;
		}
	},

	webauthn = () => window.TwoFactorWebAuthn,

	/**
	 * A current second factor, as the server takes it: { Code } or, since
	 * 2.28.0, { Assertion } from a security key. A bare string is a code.
	 */
	proofOf = proof => 'string' === typeof proof ? { Code: proof } : Object.assign({ Code: '' }, proof || {}),

	// A date, in the language of the page; the server sends seconds.
	dateOf = ts => {
		try {
			const lang = ('undefined' !== typeof document && document.documentElement && document.documentElement.lang) || undefined;
			return new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(ts * 1000));
		} catch (e) {
			return new Date(ts * 1000).toISOString().slice(0, 16).replace('T', ' ');
		}
	},

	Remote = new class {
		/**
		 * @param {?Function} fCallback
		 * @param {string} sCode
		 */
		verifyCode(fCallback, sCode) {
			rl.pluginRemoteRequest(fCallback, 'VerifyTwoFactorCode', {
				Code: sCode
			});
		}

		/**
		 * @param {?Function} fCallback
		 * @param {boolean} bEnable
		 * @param {string|Object} proof a code, or { Assertion }
		 */
		enableTwoFactor(fCallback, bEnable, proof) {
			rl.pluginRemoteRequest(fCallback, 'EnableTwoFactor', Object.assign({
				Enable: bEnable ? 1 : 0
			}, proofOf(proof)));
		}
	};

class TwoFactorAuthSettings
{

	constructor() {
		this.processing = ko.observable(false);
		this.clearing = ko.observable(false);
		this.secreting = ko.observable(false);

		// The app-password note only where the server enforces it (S-09):
		// a screen that promises a protection the server lacks misleads.
		this.appPasswordsNote = ko.observable(!!rl.settings.get('TwoFactorAppPasswords'));

		this.viewUser = ko.observable('');
		this.twoFactorStatus = ko.observable(false);

		this.twoFactorTested = ko.observable(false);

		this.viewSecret = ko.observable('');
		this.viewQRCode = ko.observable('');
		this.viewBackupCodes = ko.observable('');

		this.viewEnable_ = ko.observable(false);

		// 2.28.0: security keys and passkeys. Plain observables, set from each
		// answer of the server — no computed, nothing calculated in the template.
		this.secondFactorOn = ko.observable(false);
		this.webauthn = ko.observable(false);
		this.webauthnSupported = ko.observable(!!(webauthn() && webauthn().supported()));
		this.passkeys = ko.observableArray ? ko.observableArray([]) : ko.observable([]);
		this.hasPasskeys = ko.observable(false);
		this.maxPasskeys = ko.observable(0);
		this.canAddPasskey = ko.observable(false);
		this.newPasskeyName = ko.observable('');
		this.passkeyBusy = ko.observable(false);
		this.passkeyError = ko.observable('');

		const fn = iError => iError && this.viewEnable_(false);
		Object.entries({
			viewEnable: {
				read: this.viewEnable_,
				write: (value) => {
					value = !!value;
					if (value && this.twoFactorTested()) {
						this.viewEnable_(value);
						Remote.enableTwoFactor((iError, oData) => {
							const on = !iError && !!oData?.Result;
							fn(on ? 0 : (iError || 1));
							rl.settings.get('RequireTwoFactor') && rl.settings.set('SetupTwoFactor', !on);
						}, value);
					} else if (this.viewEnable_()) {
						// Switching it off asks for a current code (2.21.0) — or a
						// security key (2.28.0): a stolen session must not be
						// enough to drop the second factor.
						this.prove((proof, done) => Remote.enableTwoFactor((iError, oData) => {
								const ok = !iError && !!oData?.Result;
								// Off again, and no key left: the server refuses everything again (2.27.0), so the screen forces again.
								ok && rl.settings.get('RequireTwoFactor') && !this.hasPasskeys() && rl.settings.set('SetupTwoFactor', true);
								done(iError, oData);
							}, false, proof),
							() => this.viewEnable_(false));
					} else {
						Remote.enableTwoFactor(fn, false);
					}
				}
			},

			viewTwoFactorEnableTooltip: () => {
//				translatorTrigger();
				return this.twoFactorTested() || this.viewEnable_()
					? ''
					: rl.i18n('PLUGIN_2FA/TWO_FACTOR_SECRET_TEST_BEFORE_DESC');
			},

			viewTwoFactorStatus: () => {
//				translatorTrigger();
				return rl.i18n('PLUGIN_2FA/TWO_FACTOR_SECRET_'
					+ (this.twoFactorStatus() ? '' : 'NOT_')
					+ 'CONFIGURED_DESC'
				);
			},

			twoFactorAllowedEnable: () => this.viewEnable() || this.twoFactorTested()
		}).forEach(([key, fn]) => this[key] = ko.computed(fn));

		this.onResult = this.onResult.bind(this);
		this.onShowSecretResult = this.onShowSecretResult.bind(this);
		['addPasskey', 'renamePasskey', 'savePasskey', 'removePasskey'].forEach(m => this[m] = this[m].bind(this));
	}

	/**
	 * Asks for a current second factor, then runs action(proof, done): the
	 * code popup, with "use a security key" when the account has one.
	 */
	prove(action, onSuccess) {
		TwoFactorAuthTestPopupView.showModal([onSuccess || (() => {}), action, this.hasPasskeys()]);
	}

	showSecret() {
		this.secreting(true);
		rl.pluginRemoteRequest(this.onShowSecretResult, 'ShowTwoFactorSecret');
	}

	hideSecret() {
		this.viewSecret('');
		this.viewQRCode('');
		this.viewBackupCodes('');
	}

	createTwoFactor() {
		const create = (proof, done) => {
			this.processing(true);
			rl.pluginRemoteRequest((iError, oData) => {
				const ok = !iError && !!oData?.Result;
				ok ? this.onResult(iError, oData) : this.processing(false);
				done && done(ok ? 0 : (iError || 1), { Result: ok });
			}, 'CreateTwoFactorSecret', proof ? proofOf(proof) : {});
		};
		// A security key is already on (2.28.0): adding a TOTP needs a current factor.
		this.secondFactorOn() ? this.prove(create) : create();
	}

	testTwoFactor() {
		TwoFactorAuthTestPopupView.showModal([
			() => {
				this.twoFactorTested(true);
				this.viewEnable(true);
			}
		]);
	}

	clearTwoFactor() {
		const clear = (proof, done) => {
			this.hideSecret();
			this.clearing(true);
			rl.pluginRemoteRequest((iError, oData) => {
				const ok = !iError && oData && false !== oData.Result;
				ok ? (this.twoFactorTested(false), this.onResult(iError, oData)) : this.clearing(false);
				// Cleared: required again, refused again by the server (2.27.0).
				ok && rl.settings.get('RequireTwoFactor') && rl.settings.set('SetupTwoFactor', true);
				done && done(ok ? 0 : 1, { Result: ok });
			}, 'ClearTwoFactorInfo', proofOf(proof));
		};
		// Once on, removing it asks for a current code (2.21.0) or key (2.28.0).
		this.viewEnable_() || this.secondFactorOn()
			? this.prove(clear)
			: clear('');
	}

	/* ---- security keys and passkeys (2.28.0) ---- */

	applyInfo(info) {
		if (!info || !Array.isArray(info.Passkeys)) {
			return;
		}
		const never = rl.i18n('PLUGIN_2FA/PASSKEY_NEVER_USED');
		this.passkeys(info.Passkeys.map(k => ({
			ref: pString(k.Ref),
			name: ko.observable(pString(k.Name)),
			draft: ko.observable(pString(k.Name)),
			editing: ko.observable(false),
			created: k.Created ? dateOf(k.Created) : '',
			lastUsed: k.LastUsed ? dateOf(k.LastUsed) : never
		})));
		this.hasPasskeys(info.Passkeys.length > 0);
		this.secondFactorOn(!!info.On);
		this.webauthn(!!info.WebAuthn);
		this.maxPasskeys(info.MaxPasskeys | 0);
		this.canAddPasskey(!!info.WebAuthn && info.Passkeys.length < (info.MaxPasskeys | 0));
		rl.settings.get('RequireTwoFactor') && rl.settings.set('SetupTwoFactor', !info.Enrolled);
	}

	addPasskey() {
		if (!authentifie() || this.passkeyBusy()) {
			return;
		}
		if (!webauthn() || !webauthn().supported()) {
			this.passkeyError(rl.i18n('PLUGIN_2FA/PASSKEYS_UNSUPPORTED'));
			return;
		}
		const fail = key => {
				this.passkeyBusy(false);
				this.passkeyError(rl.i18n(key));
			},
			register = proof => {
				this.passkeyBusy(true);
				this.passkeyError('');
				rl.pluginRemoteRequest((iError, oData) => {
					if (iError || !oData?.Result) {
						return fail('PLUGIN_2FA/ERROR_PASSKEY_REFUSED');
					}
					webauthn().create(oData.Result).then(json => rl.pluginRemoteRequest((iError, oData) => {
						if (iError || !oData?.Result) {
							return fail('PLUGIN_2FA/ERROR_PASSKEY_REFUSED');
						}
						this.passkeyBusy(false);
						this.newPasskeyName('');
						this.applyInfo(oData.Result);
						// The first factor of the account: its backup codes, shown this once.
						oData.Result.BackupCodes && this.viewBackupCodes(pString(oData.Result.BackupCodes).replace(/[\s]+/g, '  '));
					}, 'WebAuthnRegister', Object.assign({
						Name: this.newPasskeyName(),
						Credential: json
					}, proof)), () => fail('PLUGIN_2FA/ERROR_PASSKEY_FAILED'));
				}, 'WebAuthnCreateOptions');
			};
		// Already protected: adding a key needs a current factor, checked by
		// the server with the registration itself.
		this.secondFactorOn()
			? this.prove((proof, done) => {
				done(0, { Result: true });
				register(proofOf(proof));
			})
			: register({});
	}

	renamePasskey(row) {
		row.draft(row.name());
		row.editing(!row.editing());
	}

	savePasskey(row) {
		rl.pluginRemoteRequest((iError, oData) => {
			!iError && oData?.Result
				? this.applyInfo(oData.Result)
				: this.passkeyError(rl.i18n('PLUGIN_2FA/ERROR_PASSKEY_REFUSED'));
		}, 'WebAuthnRename', { Ref: row.ref, Name: row.draft() });
	}

	removePasskey(row) {
		this.prove((proof, done) => rl.pluginRemoteRequest((iError, oData) => {
			const ok = !iError && !!oData?.Result;
			ok && this.applyInfo(oData.Result);
			done(ok ? 0 : (iError || 1), { Result: ok });
		}, 'WebAuthnRemove', Object.assign({ Ref: row.ref }, proofOf(proof))));
	}

	onShow() {
		this.appPasswordsNote(!!rl.settings.get('TwoFactorAppPasswords'));
		this.webauthnSupported(!!(webauthn() && webauthn().supported()));
		this.passkeyError('');
		this.hideSecret('');
	}

	getQr() {
		return 'otpauth://totp/' + encodeURIComponent(this.viewUser())
			+ '?secret=' + encodeURIComponent(this.viewSecret())
			+ '&issuer=' + encodeURIComponent('');
	}

	onResult(iError, oData) {
		this.processing(false);
		this.clearing(false);

		if (iError) {
			this.viewUser('');
			this.viewEnable_(false);
			this.twoFactorStatus(false);
			this.twoFactorTested(false);
			this.hideSecret('');
		} else {
			this.viewUser(pString(oData.Result.User));
			this.viewEnable_(!!oData.Result.Enable);
			this.twoFactorStatus(!!oData.Result.IsSet);
			this.twoFactorTested(!!oData.Result.Tested);

			this.viewSecret(pString(oData.Result.Secret));
			this.viewQRCode(oData.Result.QRCode);
			this.viewBackupCodes(pString(oData.Result.BackupCodes).replace(/[\s]+/g, '  '));
			this.applyInfo(oData.Result);
		}
	}

	onShowSecretResult(iError, data) {
		this.secreting(false);

		if (iError) {
			this.viewSecret('');
			this.viewQRCode('');
		} else {
			this.viewSecret(pString(data.Result.Secret));
			this.viewQRCode(pString(data.Result.QRCode));
		}
	}

	onBuild() {
		if (!authentifie()) {
			return;
		}
		this.processing(true);
		rl.pluginRemoteRequest(this.onResult, 'GetTwoFactorInfo');
	}
}

class TwoFactorAuthTestPopupView extends rl.pluginPopupView {
	constructor() {
		super('TwoFactorAuthTest');

		this.addObservables({
			code: '',
			codeStatus: null,
			testing: false,
			keyAvailable: false
		});

		ko.decorateCommands(this, {
			testCodeCommand: self => self.code() && !self.testing(),
			useKeyCommand: self => self.keyAvailable() && !self.testing()
		});
	}

	answer(proof) {
		this.testing(true);
		// ⚠️ « pas d'erreur » n'est pas « code juste » : le serveur répond
		// `false` à un mauvais code sans lever d'erreur.
		this.action((iError, oData) => {
			const ok = !iError && !!(oData && oData.Result);
			this.testing(false);
			this.codeStatus(ok);
			ok && (this.onSuccess() | this.close());
		}, proof);
	}

	testCodeCommand() {
		this.answer(this.code());
	}

	/** 2.28.0: the current factor given by a security key instead of a code. */
	useKeyCommand() {
		this.testing(true);
		rl.pluginRemoteRequest((iError, oData) => {
			if (iError || !oData?.Result) {
				this.testing(false);
				this.codeStatus(false);
				return;
			}
			window.TwoFactorWebAuthn.get(oData.Result).then(
				json => this.answer({ Assertion: json }),
				() => { this.testing(false); this.codeStatus(false); }
			);
		}, 'WebAuthnAssertOptions');
	}

	/**
	 * @param {Function} onSuccess
	 * @param {?Function} action fn(proof, done) — by default, test the code
	 * @param {boolean} withKey offer "use a security key" (the account has one)
	 */
	onShow(onSuccess, action, withKey) {
		this.code('');
		this.codeStatus(null);
		this.testing(false);
		this.keyAvailable(!!(withKey && action && window.TwoFactorWebAuthn && window.TwoFactorWebAuthn.supported()));
		this.onSuccess = onSuccess;
		this.action = action ? (done, proof) => action(proof, done) : (done, code) => Remote.verifyCode(done, code);
	}
}

rl.addSettingsViewModel(
	TwoFactorAuthSettings,
	'TwoFactorAuthSettings',
	'PLUGIN_2FA/LEGEND_TWO_FACTOR_AUTH',
	'two-factor-auth'
);

}})(window.rl);
