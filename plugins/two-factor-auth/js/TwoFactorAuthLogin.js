
(rl => {

	const
		forceTOTP = () => {
			if (rl.settings.get('SetupTwoFactor')) {
				setTimeout(() => document.location.hash = '#/settings/two-factor-auth', 50);
			}
		};

	let loginView = null,
		// 2.28.0: the request options of the account's security keys, sent
		// by the server after a right password; spent once used.
		keyOptions = null,
		wantKey = false;

	const
		webauthn = () => window.TwoFactorWebAuthn,
		dom = sel => loginView?.viewModelDom?.querySelector(sel),
		showKey = on => { const b = dom('.twofactor-key'); b && (b.hidden = !on); },
		// The password is still in the form: the key is the second step, sent
		// with it in a hidden field, through the core's own sign-in button.
		submit = () => dom('.buttonLogin')?.click(),
		useKey = () => {
			if (!keyOptions) {
				// Spent (a failed try): the form is sent again without a factor,
				// the server answers with a new challenge, and the key follows.
				wantKey = true;
				const code = dom('input[name=totp_code]');
				code && (code.value = '', code.dispatchEvent(new Event('input')));
				submit();
				return;
			}
			const options = keyOptions;
			keyOptions = null;
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
		};

	addEventListener('rl-view-model', e => {
		if ('Login' === e.detail.viewModelTemplateID) {
			loginView = e.detail;
			const container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),
				placeholder = 'PLUGIN_2FA/LABEL_TWO_FACTOR_CODE';
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
			}
		}
	});

	// The password was right and the code is missing: say so, instead of the
	// "authentication failed" that sends people to reset a good password.
	// The core sets its own message right after this event, hence the timeout.
	addEventListener('sm-user-login-response', e => {
		// An assertion is used once, whatever the answer.
		const field = dom('input[name=webauthn_assertion]');
		field && (field.value = '');
		const additional = e.detail?.data?.messageAdditional || '';
		if (e.detail?.error && loginView && /^TwoFactorCodeRequired(:|$)/.test(additional)) {
			keyOptions = webauthn()?.supported() ? webauthn().fromRefusal(additional) : null;
			showKey(!!keyOptions);
			setTimeout(() => {
				loginView.submitError(rl.i18n(keyOptions ? 'PLUGIN_2FA/ERROR_CODE_OR_KEY_REQUIRED' : 'PLUGIN_2FA/ERROR_CODE_REQUIRED'));
				loginView.submitErrorAdditional('');
				if (keyOptions && wantKey) {
					wantKey = false;
					useKey();
				} else {
					dom('input[name=totp_code]')?.focus();
				}
			}, 0);
		} else {
			wantKey = false;
			e.detail?.error || (keyOptions = null, showKey(false));
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
