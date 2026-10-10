
(rl => {

	const
		forceTOTP = () => {
			if (rl.settings.get('SetupTwoFactor')) {
				setTimeout(() => document.location.hash = '#/settings/two-factor-auth', 50);
			}
		};

	let loginView = null;

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
				+ '</div>'));
			}
		}
	});

	// The password was right and the code is missing: say so, instead of the
	// "authentication failed" that sends people to reset a good password.
	// The core sets its own message right after this event, hence the timeout.
	addEventListener('sm-user-login-response', e => {
		if (e.detail?.error && 'TwoFactorCodeRequired' === e.detail.data?.messageAdditional && loginView) {
			setTimeout(() => {
				loginView.submitError(rl.i18n('PLUGIN_2FA/ERROR_CODE_REQUIRED'));
				loginView.submitErrorAdditional('');
				loginView.viewModelDom?.querySelector('input[name=totp_code]')?.focus();
			}, 0);
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
