/**
 * two-factor-auth 2.28.0 — security keys and passkeys (WebAuthn), the
 * browser half: options from the server (base64url in JSON) to the
 * ArrayBuffers navigator.credentials wants, and the credential back to JSON.
 * The server verifies everything; nothing here decides anything.
 */
(win => {

	const
		b64u = buf => {
			const bytes = new Uint8Array(buf);
			let s = '';
			for (let i = 0; i < bytes.length; ++i) s += String.fromCharCode(bytes[i]);
			return win.btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
		},
		unb64u = str => {
			const s = win.atob(String(str).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(str).length + 3) % 4));
			const bytes = new Uint8Array(s.length);
			for (let i = 0; i < s.length; ++i) bytes[i] = s.charCodeAt(i);
			return bytes.buffer;
		},
		ids = list => (list || []).map(c => ({ type: c.type || 'public-key', id: unb64u(c.id) })),
		encode = cred => {
			const r = cred.response, out = {
				id: cred.id,
				rawId: b64u(cred.rawId),
				type: cred.type,
				response: { clientDataJSON: b64u(r.clientDataJSON) }
			};
			if (r.attestationObject) out.response.attestationObject = b64u(r.attestationObject);
			if (r.authenticatorData) out.response.authenticatorData = b64u(r.authenticatorData);
			if (r.signature) out.response.signature = b64u(r.signature);
			if (r.userHandle && r.userHandle.byteLength) out.response.userHandle = b64u(r.userHandle);
			return JSON.stringify(out);
		};

	win.TwoFactorWebAuthn = {
		b64u, unb64u, encode,

		/** Whether this browser can use a security key at all (secure context included). */
		supported: () => !!(win.PublicKeyCredential && win.navigator && win.navigator.credentials && false !== win.isSecureContext),

		/** The request options of a login or a confirmation, as the server sent them. */
		requestOptions: o => ({
			challenge: unb64u(o.challenge),
			rpId: o.rpId,
			timeout: o.timeout,
			userVerification: o.userVerification,
			allowCredentials: ids(o.allowCredentials)
		}),

		creationOptions: o => ({
			rp: o.rp,
			user: { id: unb64u(o.user.id), name: o.user.name, displayName: o.user.displayName },
			challenge: unb64u(o.challenge),
			pubKeyCredParams: o.pubKeyCredParams,
			timeout: o.timeout,
			excludeCredentials: ids(o.excludeCredentials),
			authenticatorSelection: o.authenticatorSelection,
			attestation: o.attestation
		}),

		/** An assertion, as the JSON string the server expects. */
		get: o => win.navigator.credentials.get({ publicKey: win.TwoFactorWebAuthn.requestOptions(o) }).then(encode),

		/** A new credential, as the JSON string the server expects. */
		create: o => win.navigator.credentials.create({ publicKey: win.TwoFactorWebAuthn.creationOptions(o) }).then(encode),

		/**
		 * The options appended to the login refusal ("TwoFactorCodeRequired:<base64url JSON>"),
		 * or null — the name alone means: no security key for this account.
		 */
		fromRefusal: additional => {
			const m = /^TwoFactorCodeRequired:([A-Za-z0-9_-]+)$/.exec(additional || '');
			if (!m) return null;
			try {
				const o = JSON.parse(new TextDecoder().decode(unb64u(m[1])));
				return o && 'string' === typeof o.challenge ? o : null;
			} catch (e) {
				return null;
			}
		}
	};

})(window);
