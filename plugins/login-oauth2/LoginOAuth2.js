(rl => {
	const client_id = rl.pluginSettingsGet('login-oauth2', 'client_id'),
		domains = (rl.pluginSettingsGet('login-oauth2', 'domains') || '')
			.toLowerCase().split(/[\s,;]+/).filter(s => s),
		isSupportedEmail = email => {
			email = (email || '').toLowerCase();
			if (!email.includes('@')) return false;
			// An empty list means every address, matching the server.
			return domains.length ? domains.includes(email.split('@').pop()) : true;
		},
		// The server signs the state and owns redirect_uri, so neither can be
		// tampered with here or drift from what the provider has registered.
		startOAuth = (op, opts = {}) => {
			rl.pluginRemoteRequest((iError, data) => {
				const url = data?.Result?.authUrl;
				if (!iError && url) {
					document.location = url;
				}
			}, 'LoginOAuth2AuthUrl', {
				op: op,
				email: opts.email || '',
				name: opts.name || '',
				return: opts.return || ''
			});
		},
		// The callback cannot finish an add: it arrives cross-site, so SameSite=Strict
		// withholds the session cookie and there is no way to tell who is logged in.
		// It parks the tokens and names them in the fragment instead. Take the secret
		// out of the URL straight away, since the fragment is the one place it would
		// otherwise linger (browser history); it never travels in a request, so logs
		// and Referer headers were never exposed to it.
		takeClaim = () => {
			const hash = location.hash,
				at = hash.indexOf('?');
			if (0 > at) return null;
			const params = new URLSearchParams(hash.slice(at + 1)),
				secret = params.get('oauth2claim');
			if (!secret) return null;
			params.delete('oauth2claim');
			const rest = params.toString();
			history.replaceState(null, '', location.pathname + location.search
				+ hash.slice(0, at) + (rest ? '?' + rest : ''));
			return secret;
		},
		pending = takeClaim();

	pending && sessionStorage.setItem('oauth2claim', pending);

	// Only cleared once the server has actually taken it, so a claim attempted
	// before the session is usable can still be retried rather than lost.
	let claiming = false;
	const claimIfPending = () => {
		const secret = sessionStorage.getItem('oauth2claim');
		if (!secret || claiming) return;
		claiming = true;
		rl.pluginRemoteRequest(iError => {
			claiming = false;
			if (!iError) {
				sessionStorage.removeItem('oauth2claim');
				rl.app?.loadAccountsAndIdentities?.();
			}
		}, 'LoginOAuth2Claim', { pickup: secret });
	};

	if (client_id) {
		addEventListener('sm-user-login', e => {
			const email = e.detail.get('Email') || '';
			if (isSupportedEmail(email)) {
				e.preventDefault();
				startOAuth('login', { email });
			}
		});

		addEventListener('rl-view-model', e => {
			// Any logged-in view will do, and the settings accounts view is not one
			// of them: it never reaches buildViewModel, so it raises no event here.
			if ('Login' !== e.detail.viewModelTemplateID) {
				claimIfPending();
			}

			if ('Login' === e.detail.viewModelTemplateID) {
				const
					container = e.detail.viewModelDom.querySelector('#plugin-Login-BottomControlGroup'),
					btn = Element.fromHTML('<button type="button">OAuth2</button>'),
					div = Element.fromHTML('<div class="controls"></div>');
				btn.onclick = () => {
					const input = e.detail.viewModelDom.querySelector('input[type="email"], input[name="Email"], input[name="email"], input'),
						email = (input?.value || '').toLowerCase();
					if (!email || isSupportedEmail(email)) {
						startOAuth('login', { email });
					}
				};
				div.append(btn);
				container && container.append(div);
			}

			// "Add account" popup (Settings -> Accounts -> Add account)
			if ('PopupsAccount' === e.detail.viewModelTemplateID) {
				// Only offered for a new account, never when editing one.
				if ('function' === typeof e.detail.isNew && !e.detail.isNew()) {
					return;
				}
				const root = e.detail.viewModelDom;
				if (!root) return;

				const footer = root.querySelector('footer'),
					form = root.querySelector('#accountform'),
					addButton = root.querySelector('button.buttonAddAccount');
				if (!footer || !form || !addButton) return;

				// The view model is reused, so do not stack up buttons.
				if (root.querySelector('.plugin-oauth2-add-account')) return;

				const btn = Element.fromHTML('<button type="button" class="btn plugin-oauth2-add-account" style="margin-left: 6px;">OAuth2</button>');
				btn.onclick = () => {
					const email = (form.querySelector('input[name="email"]')?.value || '').trim().toLowerCase();
					if (!isSupportedEmail(email)) {
						return;
					}
					startOAuth('add', {
						email: email,
						name: (form.querySelector('input[name="name"]')?.value || '').trim(),
						return: document.location.hash || '#/settings/accounts'
					});
				};
				footer.insertBefore(btn, addButton.nextSibling);
			}
		});
	}

})(window.rl);
