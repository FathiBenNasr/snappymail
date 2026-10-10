/**
 * two-factor-auth 2.27.0 — "enforce 2-Step Verification" held by the SERVER,
 * end to end on banc-smail: real Cyrus, real directory, an ephemeral account
 * of a domain listed in force_two_factor_domains. Nothing on production.
 *
 * Environment: A (address), MDP (password), BASE, MESURE=1 (only log the
 * actions the application calls in each phase, no verdict), CAPTURES=dir.
 * Run through ./preparer.sh, which mounts the plugin, sets the bench
 * configuration, creates and deletes the account.
 *
 * Phases: forced boot -> settings screen -> create secret -> test code ->
 * enable -> mail works without a reload -> second factor cleared again in the
 * same session -> refused again -> logout.
 */
const puppeteer = require('/app/scripts/node_modules/puppeteer');
const crypto = require('crypto');
const BASE = process.env.BASE || 'http://10.89.10.1:8932';
const A = process.env.A, MDP = process.env.MDP, MESURE = !!process.env.MESURE;
const CAPTURES = process.env.CAPTURES || '';
const pause = ms => new Promise(r => setTimeout(r, ms));
const echecs = []; let n = 0;
const verifier = (ok, quoi) => { n++; if (!ok) echecs.push(quoi); console.log((ok ? 'ok   ' : 'ÉCHEC ') + quoi); };
const NOM = 'TwoFactorSetupRequired';

// RFC 6238, SHA-1, 6 digits, 30 s — what the plugin's provider computes.
const totp = (b32, pas) => {
	const alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	let bits = '';
	for (const c of b32.replace(/=+$/, '').toUpperCase()) bits += alpha.indexOf(c).toString(2).padStart(5, '0');
	const cle = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
	const compteur = Buffer.alloc(8); compteur.writeBigUInt64BE(BigInt(pas));
	const h = crypto.createHmac('sha1', cle).update(compteur).digest();
	const o = h[h.length - 1] & 15;
	return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
};
const pasCourant = () => Math.floor(Date.now() / 30000);
// The plugin refuses a time step already used (anti-replay): wait for a new one.
const attendrePasNeuf = async dernier => { while (pasCourant() <= dernier) await pause(1000); return pasCourant(); };

(async () => {
	const nav = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox', '--disable-dev-shm-usage'] });
	const p = await nav.newPage();
	const erreurs = []; p.on('pageerror', e => erreurs.push(e.message));
	// An alert() blocks the page: note it (a "Folders error" means the boot was refused) and dismiss it.
	const alertes = []; p.on('dialog', d => { alertes.push(d.message()); d.dismiss().catch(() => {}); });
	await p.setUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36');
	await p.setViewport({ width: 1440, height: 900 });

	// What the application calls, phase by phase, and what the server answered.
	let phase = 'connexion';
	const journal = [];
	const nomRequete = r => {
		const u = new URL(r.url());
		if (u.origin !== new URL(BASE).origin) return null;
		const q = decodeURIComponent(u.search.slice(1)).split('&')[0].replace(/^\/+|\/+$/g, '');
		const sous = u.searchParams.getAll('q[]').map(s => s.replace(/^\/+|\/+$/g, '')).join('/');
		const chemins = (q + (sous ? '/' + sous : '')).split('/');
		const service = chemins[0] || '(index)';
		if (/^json$/i.test(service)) {
			let a = '';
			const corps = r.postData();
			if (corps) { try { a = JSON.parse(corps).Action || ''; } catch (e) { a = new URLSearchParams(corps).get('Action') || ''; } }
			return 'Do' + (a || chemins[2] || '?');
		}
		if (/^raw$/i.test(service)) return 'Raw' + (chemins[2] || '?');
		return 'Service:' + service;
	};
	p.on('response', async r => {
		const nom = nomRequete(r.request());
		if (!nom) return;
		let refus = '';
		if (nom.startsWith('Do')) {
			try { const j = await r.json(); refus = j && !j.Result ? (j.messageAdditional || ('code ' + j.code)) : ''; } catch (e) {}
		}
		journal.push({ phase, nom, refus });
	});

	// Direct calls, as a script holding the session would make them.
	const json = (action, prm = {}) => p.evaluate((action, prm) => new Promise(r =>
		rl.app.Remote.request(action, (err, data) => r({ err, ok: !!(data && data.Result), add: data && data.messageAdditional || '', res: data && data.Result }), prm)), action, prm);
	const plugin = (action, prm = {}) => json('Plugin' + action, prm);
	// A GET with three path segments (the token in its header, as a script
	// holding the session has it): the core never calls SetActionParams on it.
	const getNu = action => p.evaluate(a => rl.fetch('./?/Json/&q[]=/0/' + a, {})
		.then(r => r.json()).then(j => ({ ok: !!j.Result, add: j.messageAdditional || '', res: j.Result })), action);
	// no-store: the browser keeps a raw download it already received (Expires), and would answer for the server.
	const brut = (type, cle) => p.evaluate((t, k) => fetch('./?/Raw/&q[]=/0/' + t + '/&q[]=/' + k, { credentials: 'same-origin', cache: 'no-store' })
		.then(r => r.text()), type, cle);
	// The key of a raw download, as Message.requestHash builds it (accountHash included: the core checks it).
	const cleBrute = async o => Buffer.from(JSON.stringify(Object.assign(o, { accountHash: await p.evaluate(() => rl.settings.get('accountHash')) })))
		.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	const televerser = () => p.evaluate(() => { const f = new FormData(); f.append('uploader', new Blob(['essai'], { type: 'text/plain' }), 'essai.txt');
		return rl.fetch('./?/Upload/&q[]=/0/', { method: 'POST' }, f).then(r => r.text()); });

	const refuse = (r, quoi) => verifier(!r.ok && NOM === r.add, quoi + ' : refusé, et nommé (' + (r.ok ? 'accepté' : r.add || 'erreur sans nom') + ')');
	const passe = (r, quoi) => verifier(r.ok, quoi + ' : passe (' + (r.ok ? 'ok' : r.add || 'refus') + ')');
	const capture = async nom => { if (CAPTURES) await p.screenshot({ path: CAPTURES + '/' + nom + '.png' }); };

	try {
		await p.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 90000 });
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		const champ = await p.$('input[name=Email], input[type=email]');
		await champ.click({ clickCount: 3 }); await champ.type(A);
		await p.type('input[type=password]', MDP);
		phase = 'demarrage';
		await p.keyboard.press('Enter');
		await p.waitForFunction(() => true === (window.rl && rl.settings && rl.settings.get('Auth')), { timeout: 60000 });
		await pause(6000);
		// The onboarding plugin may ask for a display name: answer it, as a person would.
		await p.evaluate(() => { const d = [...document.querySelectorAll('dialog[open]')].find(x => /identit/i.test(x.textContent || '')); if (!d) return; const i = d.querySelector('input[type=text], input:not([type])'); if (i) { i.value = 'Essai'; i.dispatchEvent(new Event('input', { bubbles: true })); } const b = [...d.querySelectorAll('button')].find(x => /Enregistrer|Save/i.test(x.textContent || '')); b && b.click(); });
		await pause(1000);

		const reglages = await p.evaluate(() => ({ requis: rl.settings.get('RequireTwoFactor'), aFaire: rl.settings.get('SetupTwoFactor'), hash: location.hash }));
		verifier(true === reglages.requis && true === reglages.aFaire, 'le compte de smail.tn doit s\'enrôler (RequireTwoFactor, SetupTwoFactor)');
		phase = 'ecran-reglages';
		await p.waitForFunction(() => /two-factor-auth/.test(location.hash), { timeout: 20000 }).catch(() => {});
		await p.waitForSelector('.b-settings-two-factor', { visible: true, timeout: 20000 }).catch(() => {});
		verifier(/two-factor-auth/.test(await p.evaluate(() => location.hash)), 'renvoyé sur l\'écran de la vérification en deux étapes');
		await pause(2000);
		await capture('force-1-ecran');

		if (!MESURE) {
			// The gap 2.27.0 closes: the session alone, without the screen.
			refuse(await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 }), 'MessageList');
			refuse(await json('Message', { folder: 'INBOX', uid: 1 }), 'Message');
			refuse(await json('SendMessage', { from: A, to: A, subject: 'ne doit pas partir', plain: 'x', identityID: '' }), 'SendMessage');
			refuse(await json('AccountsAndIdentities'), 'AccountsAndIdentities (POST)');
			refuse(await getNu('AccountsAndIdentities'), 'AccountsAndIdentities en GET à trois segments, sans jeton');
			refuse(await getNu('Contacts'), 'Contacts en GET à trois segments, sans jeton');
			passe(await json('Folders'), 'Folders (liste blanche : sans lui l\'application se déconnecte au démarrage)');
			const dl = await brut('Download', await cleBrute({ folder: 'INBOX', uid: 1, mimeType: 'message/rfc822', fileName: 'x.eml' }));
			verifier('' === dl, 'Raw Download (uid 1) : corps vide (' + dl.length + ' octets)');
			const up = await televerser();
			verifier(up.includes(NOM), 'Upload (hors filter.action-params) : refusé, et nommé (' + up.slice(0, 80) + ')');
			passe(await plugin('GetTwoFactorInfo'), 'GetTwoFactorInfo (liste blanche)');
		}

		// Enrolment through the screen, as a person would.
		phase = 'creer-secret';
		const reponseSecret = p.waitForResponse(r => /CreateTwoFactorSecret/.test(r.request().postData() || ''), { timeout: 20000 });
		await p.evaluate(() => [...document.querySelectorAll('.b-settings-two-factor a.btn')].find(b => b.offsetParent && !b.classList.contains('btn-danger')).click());
		const secret = (await (await reponseSecret).json()).Result.Secret;
		verifier(/^[A-Z2-7]{16,}$/.test(secret || ''), 'le secret est créé');
		await pause(1500);
		await capture('force-2-secret');

		phase = 'tester-code';
		let pas = pasCourant();
		await p.evaluate(() => [...document.querySelectorAll('.b-settings-two-factor .g-ui-link')].find(l => l.offsetParent && /test/i.test(l.getAttribute('data-bind') || '')).click());
		await p.waitForSelector('dialog[open] input.inputName', { visible: true, timeout: 10000 });
		await p.type('dialog[open] input.inputName', totp(secret, pas));
		phase = 'activer';
		const reponseActiver = p.waitForResponse(r => /EnableTwoFactor/.test(r.request().postData() || ''), { timeout: 20000 });
		await p.keyboard.press('Enter');
		const activer = await (await reponseActiver).json();
		verifier(true === activer.Result, 'le code testé, la vérification s\'active');
		await pause(1500);
		verifier(false === await p.evaluate(() => rl.settings.get('SetupTwoFactor')), 'l\'écran ne force plus (SetupTwoFactor faux)');

		// Still on the settings: no reload (the backup codes are on screen, shown once).
		await p.evaluate(() => { window.__memeDocument = 1; location.hash = '#/settings/general'; });
		await pause(1500);
		verifier(1 === await p.evaluate(() => window.__memeDocument), 'dans les réglages, l\'activation ne recharge pas la page');
		// Leaving them: one reload, and the mailbox starts whole.
		phase = 'courrier';
		await p.evaluate(() => { location.hash = '#/mailbox/INBOX'; });
		await p.waitForFunction(() => !window.__memeDocument, { timeout: 30000 }).catch(() => {});
		verifier(await p.evaluate(() => !window.__memeDocument), 'en quittant les réglages, l\'application se recharge une fois');
		await p.waitForSelector('.buttonCompose', { visible: true, timeout: 60000 }).catch(() => {});
		await pause(4000);
		const boites = await p.evaluate(() => document.querySelectorAll('#V-MailFolderList .b-folders-user a, .b-folders .e-item').length);
		verifier(boites > 0, 'la liste des dossiers est là (' + boites + ')');
		verifier(/mailbox/.test(await p.evaluate(() => location.hash)), 'la boîte s\'ouvre, sans renvoi vers les réglages');
		const identites = await json('AccountsAndIdentities');
		verifier(identites.ok, 'les identités se chargent');
		await capture('force-3-courrier');

		let uid = 0;
		if (!MESURE) {
			passe(await json('Folders'), 'Folders, une fois enrôlé');
			passe(await getNu('AccountsAndIdentities'), 'AccountsAndIdentities en GET à trois segments, une fois enrôlé');
			const sujet = 'essai 2fa ' + Date.now();
			passe(await json('SendMessage', { from: A, to: A, subject: sujet, plain: 'corps de l\'essai', identityID: '', saveFolder: '' }), 'SendMessage, une fois enrôlé');
			for (let i = 0; i < 20 && !uid; i++) {
				await pause(1500);
				const l = await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20, search: '' });
				const m = (l.res && l.res['@Collection'] || []).find(x => x.subject === sujet);
				uid = m ? m.uid : 0;
			}
			verifier(uid > 0, 'MessageList, une fois enrôlé : le message envoyé à soi-même est arrivé (uid ' + uid + ')');
			const dl = await brut('Download', await cleBrute({ folder: 'INBOX', uid, mimeType: 'message/rfc822', fileName: 'x.eml' }));
			verifier(dl.includes(sujet), 'Raw Download, une fois enrôlé : le message (' + dl.length + ' octets)');
			passe(await json('Message', { folder: 'INBOX', uid }), 'Message, une fois enrôlé');

			// Cleared again in the same session: refused again, with a real message to refuse.
			phase = 'effacer';
			pas = await attendrePasNeuf(pas);
			passe(await plugin('ClearTwoFactorInfo', { Code: totp(secret, pas) }), 'ClearTwoFactorInfo avec un code courant');
			refuse(await json('MessageList', { folder: 'INBOX', offset: 0, limit: 20 }), 'MessageList, effacé dans la même session');
			refuse(await json('Message', { folder: 'INBOX', uid }), 'Message ' + uid + ', effacé dans la même session');
			const dl2 = await brut('Download', await cleBrute({ folder: 'INBOX', uid, mimeType: 'message/rfc822', fileName: 'x.eml' }));
			verifier('' === dl2, 'Raw Download du message réel, effacé : corps vide (' + dl2.length + ' octets)');
			refuse(await getNu('AccountsAndIdentities'), 'AccountsAndIdentities en GET à trois segments, effacé');
		}

		phase = 'deconnexion';
		await p.evaluate(() => rl.app.logout());
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 30000 }).catch(() => {});
		verifier(!!(await p.$('input[type=password]')), 'la déconnexion ramène à l\'écran de connexion');
	} catch (e) {
		verifier(false, 'le parcours a cédé : ' + e.message);
	} finally {
		await pause(500);
		console.log('\n--- actions appelées par l\'application, par phase (refus entre crochets) ---');
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
		verifier(0 === alertes.length, 'aucune alerte (ni « Folders error », ni « Logout error »)');
		console.log('\n' + n + ' contrôles, ' + echecs.length + ' échec(s)');
		process.exit(echecs.length ? 1 : 0);
	}
})();
