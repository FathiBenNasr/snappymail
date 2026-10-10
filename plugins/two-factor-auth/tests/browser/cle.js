/**
 * two-factor-auth 2.28.0 — a security key as the second factor, end to end on
 * banc-smail: real Cyrus, real directory, an ephemeral account of a domain
 * that must enrol, and Chrome's own WebAuthn stack driven by a CDP virtual
 * authenticator (WebAuthn.addVirtualAuthenticator) — the browser builds and
 * signs clientDataJSON, authenticatorData and the attestation itself.
 * Nothing on production.
 *
 * WebAuthn wants a secure context and refuses an IP address as relying party:
 * the bench is reached as http://banc-smail.test:8932 (host resolver rule to
 * 10.89.10.1), declared secure for this origin only.
 *
 * Environment: A (address), MDP (password), BASE, MESURE=1 (only log the
 * actions called in each phase), CAPTURES=dir. Run through
 * BANC=cle sh preparer.sh, which mounts the plugin, sets the bench
 * configuration, creates and deletes the account.
 *
 * Phases: forced boot -> register a key (allowed while not enrolled) -> mail
 * works -> logout -> password, then the key -> renamed -> removed with the key
 * itself -> forced again -> logout.
 */
const puppeteer = require('/app/scripts/node_modules/puppeteer');
const BASE = process.env.BASE || 'http://banc-smail.test:8932';
const HOTE = new URL(BASE).hostname;
const A = process.env.A, MDP = process.env.MDP, MESURE = !!process.env.MESURE;
const CAPTURES = process.env.CAPTURES || '';
const pause = ms => new Promise(r => setTimeout(r, ms));
const echecs = []; let n = 0;
const verifier = (ok, quoi) => { n++; if (!ok) echecs.push(quoi); console.log((ok ? 'ok   ' : 'ÉCHEC ') + quoi); };
const REFUS = 'TwoFactorSetupRequired';

(async () => {
	const nav = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox', '--disable-dev-shm-usage',
		'--host-resolver-rules=MAP ' + HOTE + ' 10.89.10.1', '--unsafely-treat-insecure-origin-as-secure=' + new URL(BASE).origin] });
	const p = await nav.newPage();
	const erreurs = []; p.on('pageerror', e => erreurs.push(e.message));
	const alertes = []; p.on('dialog', d => { alertes.push(d.message()); d.dismiss().catch(() => {}); });
	await p.setUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36');
	await p.setViewport({ width: 1280, height: 900 });

	// The authenticator: a USB security key with a PIN, always touched.
	const cdp = await p.target().createCDPSession();
	await cdp.send('WebAuthn.enable');
	const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
		protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true,
		isUserVerified: true, automaticPresenceSimulation: true } });
	const cles = async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;

	let phase = 'connexion';
	const journal = [];
	p.on('response', async r => {
		const u = new URL(r.url());
		if (u.origin !== new URL(BASE).origin || !/json/i.test(u.search)) return;
		let a = '';
		const corps = r.request().postData();
		if (corps) { try { a = JSON.parse(corps).Action || ''; } catch (e) { a = (/Action"?\s*[:=]\s*"?(\w+)/.exec(corps) || [])[1] || ''; } }
		let refus = '';
		try { const j = await r.json(); refus = j && !j.Result ? (j.messageAdditional || ('code ' + j.code)).slice(0, 40) : ''; } catch (e) {}
		journal.push({ phase, nom: 'Do' + (a || '?'), refus });
	});
	const json = (action, prm = {}) => p.evaluate((action, prm) => new Promise(r =>
		rl.app.Remote.request(action, (err, data) => r({ err, ok: !!(data && data.Result), add: data && data.messageAdditional || '', res: data && data.Result }), prm)), action, prm);
	const capture = async (nom, sel) => {
		if (!CAPTURES) return;
		const el = sel ? await p.$(sel) : null;
		await (el || p).screenshot({ path: CAPTURES + '/' + nom + '.png' });
	};
	const connecter = async () => {
		await p.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 90000 });
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		const champ = await p.$('input[name=Email], input[type=email]');
		await champ.click({ clickCount: 3 }); await champ.type(A);
		await p.type('input[type=password]', MDP);
		await p.keyboard.press('Enter');
	};
	// The onboarding plugin may ask for a display name, at each login: answer it, as a person would.
	const fermerIdentite = () => p.evaluate(() => { const d = [...document.querySelectorAll('dialog[open]')].find(x => /identit/i.test(x.textContent || '')); if (!d) return; const i = d.querySelector('input[type=text], input:not([type])'); if (i) { i.value = 'Essai'; i.dispatchEvent(new Event('input', { bubbles: true })); } const b = [...d.querySelectorAll('button')].find(x => /Enregistrer|Save/i.test(x.textContent || '')); b && b.click(); });
	const authentifie = () => p.waitForFunction(() => true === (window.rl && rl.settings && rl.settings.get('Auth')), { timeout: 60000 });

	try {
		phase = 'demarrage';
		await connecter();
		verifier(await p.evaluate(() => window.isSecureContext && !!window.PublicKeyCredential), 'contexte sûr, WebAuthn disponible pour ' + BASE);
		await authentifie();
		await pause(5000);
		await fermerIdentite();
		await p.waitForSelector('.b-settings-two-factor-keys', { visible: true, timeout: 30000 }).catch(() => {});
		verifier(true === await p.evaluate(() => rl.settings.get('SetupTwoFactor')), 'le compte doit s\'enrôler (SetupTwoFactor)');
		verifier(!!(await p.$('.b-settings-two-factor-keys:not([style*="none"])')), 'la section « Clés de sécurité » est affichée');
		if (!MESURE) {
			const r = await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 });
			verifier(!r.ok && REFUS === r.add, 'avant la clé : MessageList refusé (' + (r.add || 'accepté') + ')');
		}

		phase = 'inscrire-cle';
		await p.type('.b-settings-two-factor-keys input.uiInput', 'YubiKey du banc');
		const rep = p.waitForResponse(r => /WebAuthnRegister/.test(r.request().postData() || ''), { timeout: 30000 });
		await p.click('.twofactor-add-passkey');
		const inscrit = (await (await rep).json()).Result;
		verifier(!!inscrit && true === inscrit.On, 'la clé est inscrite (WebAuthnRegister, autorisé avant l\'enrôlement)');
		verifier(1 === (await cles()).length, 'l\'authentificateur porte une clé');
		await pause(1000);
		const ligne = await p.$eval('.twofactor-passkey', e => e.textContent.replace(/\s+/g, ' ').trim()).catch(() => '');
		verifier(/YubiKey du banc/.test(ligne), 'la clé est listée avec son nom (' + ligne.slice(0, 80) + ')');
		const secours = await p.evaluate(() => [...document.querySelectorAll('.b-settings-two-factor pre')].map(x => x.textContent.trim()).join(' '));
		verifier(8 === (secours.match(/\d{9}/g) || []).length, 'huit codes de secours affichés, une fois');
		verifier(false === await p.evaluate(() => rl.settings.get('SetupTwoFactor')), 'l\'écran ne force plus');
		await capture('cle-1-reglages', '.b-settings-two-factor');
		if (!MESURE) {
			const r = await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 });
			verifier(r.ok, 'après la clé : MessageList passe');
		}

		phase = 'deconnexion-1';
		await p.evaluate(() => rl.app.logout());
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 30000 });

		phase = 'connexion-cle';
		await connecter();
		await p.waitForSelector('.twofactor-key:not([hidden])', { visible: true, timeout: 30000 }).catch(() => {});
		verifier(!!(await p.$('.twofactor-key:not([hidden])')), 'le mot de passe juste, le bouton « clé de sécurité » apparaît');
		const message = await p.evaluate(() => (document.querySelector('.alert:not([hidden]) span') || {}).textContent || '');
		verifier(/clé|key/i.test(message), 'le message nomme le code et la clé (« ' + message.trim() + ' »)');
		// The form and the message above it: their common parent.
		await p.evaluate(() => { const f = document.querySelector('.twofactor-key').closest('form'); f && f.parentElement.setAttribute('data-capture', 'connexion'); });
		await capture('cle-2-connexion', '[data-capture=connexion]');
		const avant = (await cles())[0].signCount;
		await p.click('.twofactor-key button');
		await authentifie().catch(() => {});
		verifier(true === await p.evaluate(() => rl.settings.get('Auth')), 'connecté avec la clé, sans code');
		verifier((await cles())[0].signCount > avant, 'le compteur de la clé a avancé (' + avant + ' → ' + (await cles())[0].signCount + ')');

		phase = 'reglages';
		await pause(4000);
		await fermerIdentite();
		await pause(1000);
		await p.evaluate(() => { location.hash = '#/settings/two-factor-auth'; });
		await p.waitForSelector('.twofactor-passkey', { visible: true, timeout: 30000 }).catch(() => {});
		const usage = await p.$eval('.twofactor-passkey', e => e.textContent).catch(() => '');
		verifier(!/Jamais|Never/.test(usage), 'la dernière utilisation est datée');

		phase = 'renommer';
		await p.evaluate(() => [...document.querySelectorAll('.twofactor-passkey .g-ui-link')].find(l => /renamePasskey/.test(l.getAttribute('data-bind'))).click());
		const champNom = await p.$('.twofactor-passkey input.uiInput');
		await champNom.click({ clickCount: 3 }); await champNom.type('Clé du bureau');
		const repNom = p.waitForResponse(r => /WebAuthnRename/.test(r.request().postData() || ''), { timeout: 20000 });
		await p.evaluate(() => [...document.querySelectorAll('.twofactor-passkey .g-ui-link')].find(l => /savePasskey/.test(l.getAttribute('data-bind'))).click());
		await repNom; await pause(500);
		const lignes = await p.$$eval('.twofactor-passkey', l => l.map(e => (e.offsetParent ? 'visible: ' : 'cachée: ') + e.textContent.replace(/\s+/g, ' ').trim()));
		verifier(lignes.some(l => /^visible: Clé du bureau/.test(l)), 'renommée (' + lignes.join(' | ') + ')');

		phase = 'retirer';
		await p.evaluate(() => [...document.querySelectorAll('.twofactor-passkey .g-ui-link')].find(l => /removePasskey/.test(l.getAttribute('data-bind'))).click());
		await p.waitForFunction(() => [...document.querySelectorAll('dialog[open] a.btn')].some(b => /useKeyCommand/.test(b.getAttribute('data-bind'))), { timeout: 10000 }).catch(() => {});
		const boutonCle = await p.evaluateHandle(() => [...document.querySelectorAll('dialog[open] a.btn')].find(b => b.offsetParent && /useKeyCommand/.test(b.getAttribute('data-bind'))));
		verifier(!!(await boutonCle.evaluate(b => !!b)), 'retirer demande un second facteur, et la clé est proposée');
		await pause(1000); // the dialog slides in
		await capture('cle-3-retirer', 'dialog[open]:has(a[data-bind*=useKeyCommand])');
		const repRetrait = p.waitForResponse(r => /WebAuthnRemove/.test(r.request().postData() || ''), { timeout: 30000 });
		await boutonCle.evaluate(b => b.click());
		const retrait = (await (await repRetrait).json()).Result;
		verifier(!!retrait && 0 === retrait.Passkeys.length, 'retirée, confirmée par la clé elle-même');
		await pause(1000);
		verifier(true === await p.evaluate(() => rl.settings.get('SetupTwoFactor')), 'plus aucun facteur : l\'écran force de nouveau');
		if (!MESURE) {
			const r = await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 });
			verifier(!r.ok && REFUS === r.add, 'plus aucun facteur : MessageList refusé de nouveau');
		}

		phase = 'deconnexion';
		await p.evaluate(() => rl.app.logout());
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 30000 }).catch(() => {});
	} catch (e) {
		verifier(false, 'le parcours a cédé : ' + e.message);
	} finally {
		console.log('\n--- actions appelées, par phase (refus entre crochets) ---');
		const vu = new Map();
		for (const { phase: ph, nom, refus } of journal) {
			const cle = ph + ' ' + nom + (refus ? ' [' + refus + ']' : '');
			vu.set(cle, (vu.get(cle) || 0) + 1);
		}
		for (const [cle, k] of vu) console.log('  ' + cle + (k > 1 ? ' ×' + k : ''));
		const pe = erreurs.filter(e => !/ResizeObserver/.test(e));
		console.log('pageerror : ' + (pe.length ? pe.join(' | ') : 'aucune'));
		console.log('alert() : ' + (alertes.length ? alertes.join(' | ') : 'aucune'));
		await nav.close();
		if (MESURE) { console.log('\nmesure seule'); process.exit(0); }
		verifier(0 === pe.length, 'aucune erreur de page');
		verifier(0 === alertes.length, 'aucune alerte');
		console.log('\n' + n + ' contrôles, ' + echecs.length + ' échec(s)');
		process.exit(echecs.length ? 1 : 0);
	}
})();
