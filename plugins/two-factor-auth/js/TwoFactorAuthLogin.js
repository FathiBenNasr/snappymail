
(rl => {

	const
		forceTOTP = () => {
			if (rl.settings.get('SetupTwoFactor')) {
				setTimeout(() => document.location.hash = '#/settings/two-factor-auth', 50);
			}
		};

	let loginView = null,
		// 2.28.0: the request options of the account's security keys, sent
		// by the server after a right password; spent once used. Since
		// 2.31.0 the login screen asks for them itself, before the password.
		keyOptions = null;

	const
		webauthn = () => window.TwoFactorWebAuthn,
		dom = sel => loginView?.viewModelDom?.querySelector(sel),
		showKey = on => { const b = dom('.twofactor-key'); b && (b.hidden = !on); },
		// 2.31.0: offered from the start wherever keys are on — for every
		// visitor, so the button says nothing about any account.
		keyLogin = () => !!(rl.settings.get('TwoFactorKeyLogin') && webauthn()?.supported()),
		sign = options => {
			webauthn().get(options).then(json => {
				const field = dom('input[name=webauthn_assertion]');
				if (field) {
					field.value = json;
					submit();
				}
			}, () => {
				// Cancelled, timed out, or no such key here: say so, the code stays possible.
				loginView.submitError(rl.i18n('PLUGIN_2FA/ERROR_PASSKEY_FAILED'));
			});
		},
		// The password is still in the form: the key is the second step, sent
		// with it in a hidden field, through the core's own sign-in button.
		submit = () => dom('.buttonLogin')?.click(),
		useKey = () => {
			if (keyOptions) {
				const options = keyOptions;
				keyOptions = null;
				sign(options);
				return;
			}
			// The challenge is asked for this address, before any password: the
			// server judges the key first, and the password only then.
			const email = String(dom('input[name=Email]')?.value || '').trim();
			if (!email) {
				loginView.submitError(rl.i18n('PLUGIN_2FA/ERROR_EMAIL_FOR_KEY'));
				dom('input[name=Email]')?.focus();
				return;
			}
			const code = dom('input[name=totp_code]');
			code && (code.value = '', code.dispatchEvent(new Event('input')));
			rl.pluginRemoteRequest((error, data) => {
				const options = !error && data?.Result;
				options && 'string' === typeof options.challenge
					? sign(options)
					: loginView.submitError(rl.i18n('PLUGIN_2FA/ERROR_PASSKEY_FAILED'));
			}, 'WebAuthnLoginOptions', { Email: email });
		};

	addEventListener('rl-view-model', e => {
		if ('Login' === e.detail.viewModelTemplateID) {
			loginView = e.detail;
			const container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),
				// 2.32.0: says "or a backup code" to every visitor, the same way:
				// a person without their key must see that a way in exists.
				placeholder = 'PLUGIN_2FA/PLACEHOLDER_LOGIN_CODE';
			if (container) {
				container.prepend(Element.fromHTML('<div class="controls">'
					+ '<span class="fontastic">⏱</span>'
					+ '<input name="totp_code" type="text" class="input-block-level"'
					+ ' pattern="[0-9]*" inputmode="numeric"'
					+ ' autocomplete="one-time-code" autocorrect="off" autocapitalize="none"'
					+ ' data-bind="textInput: totp, disable: submitRequest" data-i18n="[placeholder]'+placeholder
					+ '" placeholder="'+rl.i18n(placeholder)+'">'
				+ '<input name="webauthn_assertion" type="hidden" value="">'
				+ '</div>'));
				// Shown only once the server has said this account has a key.
				const button = Element.fromHTML('<div class="controls twofactor-key" hidden="">'
					+ '<button type="button" class="btn" data-i18n="PLUGIN_2FA/BUTTON_USE_PASSKEY">'
					+ rl.i18n('PLUGIN_2FA/BUTTON_USE_PASSKEY') + '</button></div>');
				button.querySelector('button')?.addEventListener('click', useKey);
				container.append(button);
				showKey(keyLogin());
			}
		}
	});

	// The password was right and the code is missing: say so, instead of the
	// "authentication failed" that sends people to reset a good password.
	// The core sets its own message right after this event, in the same task
	// (Login.js: fireEvent, then submitError and submitErrorAdditional). A
	// microtask runs after that code and BEFORE the browser paints; the
	// setTimeout of 2.28.0 ran after a paint, and the refusal — the key's
	// request options in base64url — showed for a frame under the error.
	addEventListener('sm-user-login-response', e => {
		// An assertion is used once, whatever the answer.
		const field = dom('input[name=webauthn_assertion]');
		field && (field.value = '');
		const additional = e.detail?.data?.messageAdditional || '';
		if (e.detail?.error && loginView && /^TwoFactorCodeRequired(:|$)/.test(additional)) {
			keyOptions = webauthn()?.supported() ? webauthn().fromRefusal(additional) : null;
			showKey(!!keyOptions || keyLogin());
			queueMicrotask(() => {
				loginView.submitError(rl.i18n(keyOptions ? 'PLUGIN_2FA/ERROR_CODE_OR_KEY_REQUIRED' : 'PLUGIN_2FA/ERROR_CODE_REQUIRED'));
				loginView.submitErrorAdditional('');
				dom('input[name=totp_code]')?.focus();
			});
		} else {
			e.detail?.error || (keyOptions = null, showKey(false));
			// 2.30.0: the server judges the code before the password, and a
			// login without the code is refused like a wrong password — saying
			// "code required" there would tell anyone who has a second factor.
			// The reminder is decided here, from the empty field alone, so it
			// shows for every account and says nothing about this one.
			// 2.32.0: for EVERY refusal of the credentials (code empty or not,
			// right password or not): the same text, so it still says nothing of
			// the account — and a person with a wrong code is told that a backup
			// code, or the key, also opens it.
			if (102 === e.detail?.error && loginView) {
				queueMicrotask(() => loginView.submitErrorAdditional(rl.i18n(keyLogin()
					? 'PLUGIN_2FA/HINT_CODE_OR_KEY_WITH_PASSWORD' : 'PLUGIN_2FA/HINT_CODE_WITH_PASSWORD')));
			}
		}
	});

	// https://github.com/the-djmaze/snappymail/issues/349
	// Since 2.27.0 the server refuses, until the second factor is on, what the
	// mailbox loads at boot (identities, the data of other plugins): leaving
	// the settings once enrolled reloads the application, which then starts
	// whole. Not on enabling itself — the backup codes are still on screen,
	// and they are shown only once.
	let forced = false;
	addEventListener('sm-show-screen', e => {
		const settings = e.detail.startsWith('settings');
		if (rl.settings.get('SetupTwoFactor')) {
			forced = true;
			if (!settings) {
				e.preventDefault();
				forceTOTP();
			}
		} else if (forced && !settings) {
			e.preventDefault();
			document.location.reload();
		}
	});

})(window.rl);
