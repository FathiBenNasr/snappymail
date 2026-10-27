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
 * Phases: forced boot -> register a key (allowed while not enrolled) -> since
 * 2.32.0 it is put aside with eight backup codes, which leave the screen and
 * must be proven kept by retyping the one asked -> only then mail works ->
 * logout -> password, then the key -> the same screens in English and Arabic,
 * with new backup codes proven in each -> renamed -> removed with the key
 * itself -> forced again -> logout.
 */
const puppeteer = require('/app/scripts/node_modules/puppeteer');
const fs = require('fs');
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
	// The base run is in French (the captures without a language suffix); en and ar follow.
	await p.setExtraHTTPHeaders({ 'Accept-Language': 'fr' });

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
		// Captures are published (the repository is mirrored to GitHub): backup
		// codes are masked in the page before the shot, even for a throw-away account.
		await p.evaluate(() => document.querySelectorAll('pre').forEach(e => {
			if (/\d{8}/.test(e.textContent)) e.textContent = '•••••••• ••••••••';
		}));
		await (el || p).screenshot({ path: CAPTURES + '/' + nom + '.png' });
	};
	// 2.31.0: the failures the directory counted, asked of the host (preparer.sh), as in avant.js.
	const echecsAnnuaire = async etape => {
		try { fs.unlinkSync('/essai/two-factor-auth/lu'); } catch (e) {}
		fs.writeFileSync('/essai/two-factor-auth/etape', etape);
		for (let i = 0; i < 120; i++) {
			await pause(500);
			try { const s = fs.readFileSync('/essai/two-factor-auth/lu', 'utf8').trim(); if (/^\d+$/.test(s)) return +s; } catch (e) {}
		}
		return null;
	};
	// 2.32.0: the backup codes on screen, then the proof, then the confirmation.
	const codesAffiches = () => p.evaluate(() => [...document.querySelectorAll('.b-settings-two-factor pre')].map(x => x.textContent.trim()).join(' ').match(/\d{9}/g) || []);
	const attendre = (action, declencheur) => {
		const r = p.waitForResponse(x => new RegExp(action).test(x.request().postData() || ''), { timeout: 30000 });
		return declencheur().then(() => r).then(x => x.json());
	};
	// Shows the proof screen (codes hidden), tries a wrong code, then the right one.
	const prouver = async (info, codes, suffixe) => {
		verifier(!!(await p.$('.twofactor-codes-saved')) && await p.$eval('.twofactor-codes-saved', e => !!e.offsetParent), suffixe + 'le bouton « je les ai gardés » est là');
		await capture('cle-1-codes' + (suffixe.split(' ')[0] ? '-' + suffixe.split(' ')[0] : ''), '.b-settings-two-factor');
		await p.click('.twofactor-codes-saved');
		await pause(500);
		verifier(0 === (await codesAffiches()).length, suffixe + 'les codes ont quitté l\'écran');
		const etiquette = await p.$eval('.twofactor-pending label[for=twofactor-confirm-code]', e => e.textContent).catch(() => '');
		verifier(etiquette.includes(String(info.PendingAsk)), suffixe + 'la preuve demande le code n° ' + info.PendingAsk + ' (« ' + etiquette + ' »)');
		await p.type('.twofactor-confirm-code', '000000000');
		const mauvais = await attendre('ConfirmBackupCodes', () => p.click('.twofactor-confirm'));
		await pause(800);
		verifier(!mauvais.Result && await p.$eval('.twofactor-pending .alert', e => !!e.offsetParent && e.textContent.trim().length > 0).catch(() => false), suffixe + 'un faux code est refusé, avec un message');
		await capture('cle-1-preuve' + (suffixe.split(' ')[0] ? '-' + suffixe.split(' ')[0] : ''), '.b-settings-two-factor');
		const champ = await p.$('.twofactor-confirm-code');
		await champ.click({ clickCount: 3 }); await champ.type(codes[info.PendingAsk - 1]);
		return attendre('ConfirmBackupCodes', () => p.click('.twofactor-confirm'));
	};
	// A new set of codes, asked with the key; the old ones hold until the proof.
	const regenerer = async suffixe => {
		const ouvre = p.evaluate(() => document.querySelector('.twofactor-regenerate').click());
		await p.waitForFunction(() => [...document.querySelectorAll('dialog[open] a.btn')].some(b => /useKeyCommand/.test(b.getAttribute('data-bind'))), { timeout: 10000 });
		await ouvre; await pause(1000);
		const rep = p.waitForResponse(x => /RegenerateBackupCodes/.test(x.request().postData() || ''), { timeout: 30000 });
		await p.evaluate(() => [...document.querySelectorAll('dialog[open] a.btn')].find(b => b.offsetParent && /useKeyCommand/.test(b.getAttribute('data-bind'))).click());
		const info = (await (await rep).json()).Result;
		await pause(800);
		verifier(!!info && true === info.Pending && false === info.PendingKey, suffixe + 'régénérer (confirmé par la clé) : huit codes en attente, sans nouvelle clé');
		const codes = await codesAffiches();
		verifier(8 === codes.length, suffixe + 'huit nouveaux codes affichés une fois');
		const fin = await prouver(info, codes, suffixe);
		verifier(!!fin.Result && 8 === fin.Result.BackupLeft && false === fin.Result.Pending, suffixe + 'codes confirmés : huit en vigueur');
		await pause(500);
	};
	const reponseLogin = () => p.waitForResponse(r => 'POST' === r.request().method() && /"Action":"Login"/.test(r.request().postData() || ''), { timeout: 60000 })
		.then(r => r.json()).catch(() => ({}));
	const connecter = async (mdp = MDP, envoyer = true) => {
		await p.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 90000 });
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		// 2.29.0: the refusal carries the key's request options; count every
		// painted frame where it shows. requestAnimationFrame runs just before
		// a paint, so a frame that would show it is a frame counted here.
		await p.evaluate(() => {
			window.__defiPeint = 0;
			const f = () => { (document.body.innerText || '').includes('TwoFactorCodeRequired') && window.__defiPeint++; requestAnimationFrame(f); };
			requestAnimationFrame(f);
		});
		const champ = await p.$('input[name=Email], input[type=email]');
		await champ.click({ clickCount: 3 }); await champ.type(A);
		await p.type('input[type=password]', mdp);
		envoyer && await p.keyboard.press('Enter');
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
		verifier(await p.$eval('.twofactor-sole-note', e => !!e.offsetParent && /seul second facteur/.test(e.textContent)).catch(() => false), 'avant la clé : l\'écran dit qu\'elle sera le seul second facteur');
		await capture('cle-0-note', '.b-settings-two-factor-keys');
		await p.type('.b-settings-two-factor-keys input.uiInput', 'YubiKey du banc');
		const rep = p.waitForResponse(r => /WebAuthnRegister/.test(r.request().postData() || ''), { timeout: 30000 });
		await p.click('.twofactor-add-passkey');
		const inscrit = (await (await rep).json()).Result;
		verifier(!!inscrit && false === inscrit.On && true === inscrit.Pending && true === inscrit.PendingKey, 'la clé est mise de côté, pas active (On ' + (inscrit && inscrit.On) + ', Pending ' + (inscrit && inscrit.Pending) + ')');
		verifier(1 === (await cles()).length, 'l\'authentificateur porte une clé');
		await pause(1000);
		const secours = await codesAffiches();
		verifier(8 === secours.length, 'huit codes de secours affichés, une fois');
		verifier(true === await p.evaluate(() => rl.settings.get('SetupTwoFactor')), 'tant que les codes ne sont pas prouvés : l\'écran force toujours');
		if (!MESURE) {
			const r = await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 });
			verifier(!r.ok && REFUS === r.add, 'tant que les codes ne sont pas prouvés : MessageList refusé');
		}
		const confirme = (await prouver(inscrit, secours, '')).Result;
		verifier(!!confirme && true === confirme.On && true === confirme.OnlyKey && 1 === confirme.Passkeys.length, 'le bon code : la clé est active, seule (On, OnlyKey)');
		await pause(1000);
		const ligne = await p.$eval('.twofactor-passkey', e => e.textContent.replace(/\s+/g, ' ').trim()).catch(() => '');
		verifier(/YubiKey du banc/.test(ligne), 'la clé est listée avec son nom (' + ligne.slice(0, 80) + ')');
		verifier(false === await p.evaluate(() => rl.settings.get('SetupTwoFactor')), 'l\'écran ne force plus');
		verifier(await p.$eval('.twofactor-only-key', e => !!e.offsetParent && /seul|only|الوحيد/.test(e.textContent)).catch(() => false), 'l\'avertissement « clé seule » est affiché en permanence');
		verifier(await p.$eval('.twofactor-add-authenticator', e => !!e.offsetParent).catch(() => false), '… avec le bouton pour ajouter une application à codes');
		verifier(await p.$eval('.twofactor-regenerate', e => !!e.offsetParent).catch(() => false), 'le bouton « Régénérer les codes de secours » est là');
		await capture('cle-1-avertissement', '.twofactor-only-key');
		await capture('cle-1-reglages', '.b-settings-two-factor');
		if (!MESURE) {
			const r = await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 });
			verifier(r.ok, 'après la preuve : MessageList passe');
		}
		// The warning survives a reload of the page: it is read from the server.
		await p.reload({ waitUntil: 'domcontentloaded' });
		await authentifie(); await pause(4000); await fermerIdentite();
		await p.evaluate(() => { location.hash = '#/settings/two-factor-auth'; });
		await p.waitForSelector('.twofactor-only-key', { visible: true, timeout: 30000 }).catch(() => {});
		verifier(await p.$eval('.twofactor-only-key', e => !!e.offsetParent).catch(() => false), 'rechargée, la page affiche encore l\'avertissement');

		phase = 'deconnexion-1';
		await p.evaluate(() => rl.app.logout());
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 30000 });

		phase = 'connexion-cle';
		// 2.31.0: the key is judged before the password. No factor: refused
		// like a wrong password, and the directory counts nothing.
		const n0 = await echecsAnnuaire('cle-inscrite');
		await p.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 90000 });
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		verifier(!!(await p.$('.twofactor-key:not([hidden])')), 'le bouton « clé de sécurité » est là d\'emblée, avant toute adresse : pour tout visiteur');
		const rappels = [];
		for (const [quoi, mdp] of [['mot de passe faux, sans facteur', 'Faux' + MDP.slice(4)], ['mot de passe juste, sans facteur', MDP]]) {
			const r = reponseLogin();
			await connecter(mdp);
			const j = await r;
			verifier(!j.Result && 102 === j.code && '' === (j.messageAdditional || ''), quoi + ' : refusé comme un mot de passe faux, sans nommer la clé (code ' + j.code + ', « ' + (j.messageAdditional || '') + ' »)');
			await pause(800);
			const rappel = await p.evaluate(() => (document.body.innerText.match(/[^\n]*(code de secours|backup code|رمز احتياطي)[^\n]*/) || [''])[0].trim());
			rappels.push(rappel);
			verifier(/secours/.test(rappel), quoi + ' : le rappel cite le code de secours (« ' + rappel.slice(0, 60) + '… »)');
		}
		verifier(2 === rappels.length && rappels[0] === rappels[1], 'le rappel est identique pour les deux refus');
		const n1 = await echecsAnnuaire('cle-refus');
		verifier(null !== n0 && n1 === n0, 'ces deux refus n\'ont pas atteint l\'annuaire : ' + n0 + ' → ' + n1 + ' échec(s)');
		await connecter(MDP, false);
		await pause(500);
		verifier(0 === await p.evaluate(() => window.__defiPeint), 'le défi de la clé n\'est peint à aucune image (' + await p.evaluate(() => window.__defiPeint) + ')');
		// The form and the message above it: their common parent.
		await p.evaluate(() => { const f = document.querySelector('.twofactor-key').closest('form'); f && f.parentElement.setAttribute('data-capture', 'connexion'); });
		await capture('cle-2-connexion', '[data-capture=connexion]');
		const avant = (await cles())[0].signCount;
		await p.click('.twofactor-key button');
		await authentifie().catch(() => {});
		verifier(true === await p.evaluate(() => rl.settings.get('Auth')), 'connecté avec la clé, sans code');
		verifier((await cles())[0].signCount > avant, 'le compteur de la clé a avancé (' + avant + ' → ' + (await cles())[0].signCount + ')');

		// 2.29.0: the same login, and the settings, in English and in Arabic —
		// the language comes from Accept-Language (determine_user_language).
		for (const [langue, motif] of [['en', /key/i], ['ar', /مفتاح/]]) {
			phase = 'connexion-cle-' + langue;
			await p.evaluate(() => rl.app.logout());
			await p.waitForSelector('input[type=password]', { visible: true, timeout: 30000 });
			await p.setExtraHTTPHeaders({ 'Accept-Language': langue });
			await connecter(MDP, false);
			await p.waitForSelector('.twofactor-key:not([hidden])', { visible: true, timeout: 30000 }).catch(() => {});
			const bouton = await p.$eval('.twofactor-key button', b => b.textContent.trim()).catch(() => '');
			verifier(motif.test(bouton), langue + ' : le bouton parle la langue (« ' + bouton + ' »)');
			const sens = await p.evaluate(() => getComputedStyle(document.querySelector('.twofactor-key')).direction);
			verifier(('ar' === langue ? 'rtl' : 'ltr') === sens, langue + ' : sens de l\'écran ' + sens);
			await pause(500);
			verifier(0 === await p.evaluate(() => window.__defiPeint), langue + ' : le défi n\'est peint à aucune image');
			await p.evaluate(() => { const f = document.querySelector('.twofactor-key').closest('form'); f && f.parentElement.setAttribute('data-capture', 'connexion'); });
			await capture('cle-2-connexion-' + langue, '[data-capture=connexion]');
			await p.click('.twofactor-key button');
			await authentifie().catch(() => {});
			verifier(true === await p.evaluate(() => rl.settings.get('Auth')), langue + ' : connecté avec la clé');
			await pause(4000);
			await fermerIdentite();
			await p.evaluate(() => { location.hash = '#/settings/two-factor-auth'; });
			await p.waitForSelector('.twofactor-passkey', { visible: true, timeout: 30000 }).catch(() => {});
			await pause(1000);
			const sensReglages = await p.evaluate(() => getComputedStyle(document.querySelector('.b-settings-two-factor') || document.body).direction);
			verifier(('ar' === langue ? 'rtl' : 'ltr') === sensReglages, langue + ' : réglages en ' + sensReglages);
			// An empty field with dir="auto" is ltr whatever the page: its Arabic
			// placeholder came out word-reversed around « YubiKey » (2.29.0).
			const sensChamp = await p.evaluate(() => { const i = document.querySelector('.twofactor-add-passkey').parentElement.querySelector('input.uiInput'); return i ? getComputedStyle(i).direction : '?'; });
			verifier(('ar' === langue ? 'rtl' : 'ltr') === sensChamp, langue + ' : champ du nom, vide, en ' + sensChamp);
			// The key's name is Latin inside an Arabic line: it must stay whole and in order.
			const nomCle = await p.$eval('.twofactor-passkey', e => e.textContent).catch(() => '');
			verifier(/YubiKey du banc/.test(nomCle), langue + ' : le nom de la clé reste lisible');
			await capture('cle-1-reglages-' + langue, '.b-settings-two-factor');
			await capture('cle-1-avertissement-' + langue, '.twofactor-only-key');
			verifier(await p.$eval('.twofactor-only-key', e => !!e.offsetParent && /seul|only|الوحيد/.test(e.textContent)).catch(() => false), langue + ' : l\'avertissement « clé seule » est affiché');
			await regenerer(langue + ' : ');
		}
		await p.setExtraHTTPHeaders({ 'Accept-Language': 'fr' });

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
