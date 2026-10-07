
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
	addEventListener('sm-show-screen', e => {
		if (!e.detail.startsWith('settings') && rl.settings.get('SetupTwoFactor')) {
			e.preventDefault();
			forceTOTP();
		}
	});

})(window.rl);
