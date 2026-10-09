/*
import { trigger as translatorTrigger } from 'Common/Translator';
*/

(rl => { if (rl) {

const
	pString = value => null != value ? '' + value : '',

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
		 */
		enableTwoFactor(fCallback, bEnable, sCode) {
			rl.pluginRemoteRequest(fCallback, 'EnableTwoFactor', {
				Enable: bEnable ? 1 : 0,
				Code: sCode || ''
			});
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

		const fn = iError => iError && this.viewEnable_(false);
		Object.entries({
			viewEnable: {
				read: this.viewEnable_,
				write: (value) => {
					value = !!value;
					if (value && this.twoFactorTested()) {
						this.viewEnable_(value);
						Remote.enableTwoFactor(iError => {
							fn(iError);
							rl.settings.get('RequireTwoFactor') && rl.settings.set('SetupTwoFactor', !!iError);
						}, value);
					} else if (this.viewEnable_()) {
						// Switching it off asks for a current code (2.21.0): a
						// stolen session must not be enough to drop the second factor.
						TwoFactorAuthTestPopupView.showModal([
							() => this.viewEnable_(false),
							(code, done) => Remote.enableTwoFactor(done, false, code)
						]);
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
		this.processing(true);
		rl.pluginRemoteRequest(this.onResult, 'CreateTwoFactorSecret');
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
		const clear = (code, done) => {
			this.hideSecret();
			this.clearing(true);
			rl.pluginRemoteRequest((iError, oData) => {
				const ok = !iError && oData && false !== oData.Result;
				ok ? (this.twoFactorTested(false), this.onResult(iError, oData)) : this.clearing(false);
				done && done(ok ? 0 : 1, { Result: ok });
			}, 'ClearTwoFactorInfo', { Code: code || '' });
		};
		// Once on, removing it asks for a current code (2.21.0).
		this.viewEnable_()
			? TwoFactorAuthTestPopupView.showModal([() => {}, clear])
			: clear('');
	}

	onShow() {
		this.appPasswordsNote(!!rl.settings.get('TwoFactorAppPasswords'));
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
			testing: false
		});

		ko.decorateCommands(this, {
			testCodeCommand: self => self.code() && !self.testing()
		});
	}

	testCodeCommand() {
		this.testing(true);
		// ⚠️ « pas d'erreur » n'est pas « code juste » : le serveur répond
		// `false` à un mauvais code sans lever d'erreur.
		this.action((iError, oData) => {
			const ok = !iError && !!(oData && oData.Result);
			this.testing(false);
			this.codeStatus(ok);
			ok && (this.onSuccess() | this.close());
		}, this.code());
	}

	/**
	 * @param {Function} onSuccess
	 * @param {?Function} action fn(code, done) — by default, test the code
	 */
	onShow(onSuccess, action) {
		this.code('');
		this.codeStatus(null);
		this.testing(false);
		this.onSuccess = onSuccess;
		this.action = action ? (done, code) => action(code, done) : (done, code) => Remote.verifyCode(done, code);
	}
}

rl.addSettingsViewModel(
	TwoFactorAuthSettings,
	'TwoFactorAuthSettings',
	'PLUGIN_2FA/LEGEND_TWO_FACTOR_AUTH',
	'two-factor-auth'
);

}})(window.rl);
