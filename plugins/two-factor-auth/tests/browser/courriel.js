/**
 * two-factor-auth 2.33.0 / 2.34.0 — the code by the recovery address, end to
 * end on banc-smail: real Cyrus, real directory, an ephemeral account. The
 * host stands in for the console: preparer.sh (BANC=courriel) wrote a
 * verified recovery address in the bench's etat/, hands the queued codes to
 * this script when asked, and turns the domain off when asked. Nothing on
 * production; nothing is mailed.
 *
 * Phases: settings show the masked address -> a code is sent, typed, the
 * factor switched on (first factor: eight backup codes, proven) -> logout ->
 * at the login screen, a code asked with the address only, then a wrong code
 * refused, then the right one with the password -> the domain turns the code
 * off -> no code is queued any more, the section is gone, a backup code still
 * opens the account.
 *
 * Environment: A (address), MDP (password), BASE, CAPTURES=dir.
 */
const puppeteer = require('/app/scripts/node_modules/puppeteer');
const fs = require('fs');
const BASE = process.env.BASE || 'http://10.89.10.1:8932';
const A = process.env.A, MDP = process.env.MDP;
const CAPTURES = process.env.CAPTURES || '';
const pause = ms => new Promise(r => setTimeout(r, ms));
const echecs = []; let n = 0;
const verifier = (ok, quoi) => { n++; if (!ok) echecs.push(quoi); console.log((ok ? 'ok   ' : 'ÉCHEC ') + quoi); };

// Ask the host (preparer.sh): "code" -> the code queued for the console, or
// "aucun"; "eteindre" -> the domain's policy is written.
const hote = async etape => {
	try { fs.unlinkSync('/essai/two-factor-auth/lu'); } catch (e) {}
	fs.writeFileSync('/essai/two-factor-auth/etape', etape);
	for (let i = 0; i < 60; i++) {
		await pause(500);
		try { const s = fs.readFileSync('/essai/two-factor-auth/lu', 'utf8').trim(); if (s) return s; } catch (e) {}
	}
	return '';
};

(async () => {
	const nav = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox', '--disable-dev-shm-usage'] });
	const p = await nav.newPage();
	const erreurs = []; p.on('pageerror', e => erreurs.push(e.message));
	p.on('dialog', d => d.dismiss().catch(() => {}));
	await p.setUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36');
	await p.setViewport({ width: 1280, height: 900 });
	await p.setExtraHTTPHeaders({ 'Accept-Language': 'fr' });

	const capture = async (nom, sel) => {
		if (!CAPTURES) return;
		await p.evaluate(() => document.querySelectorAll('pre').forEach(e => {
			if (/\d{8}/.test(e.textContent)) e.textContent = '•••••••• ••••••••';
		}));
		const el = sel ? await p.$(sel) : null;
		await (el || p).screenshot({ path: CAPTURES + '/' + nom + '.png' });
	};
	const attendre = (action, declencheur) => {
		const r = p.waitForResponse(x => new RegExp(action).test(x.request().postData() || ''), { timeout: 30000 });
		return declencheur().then(() => r).then(x => x.json());
	};
	const codesAffiches = () => p.evaluate(() => [...document.querySelectorAll('.b-settings-two-factor pre')].map(x => x.textContent.trim()).join(' ').match(/\d{9}/g) || []);
	const reponseLogin = () => p.waitForResponse(r => 'POST' === r.request().method() && /"Action":"Login"/.test(r.request().postData() || ''), { timeout: 60000 })
		.then(r => r.json()).catch(() => ({}));
	const ecranConnexion = async () => {
		await p.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 90000 });
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		await pause(1500);
	};
	const remplir = async (sel, val) => { const c = await p.$(sel); await c.click({ clickCount: 3 }); await p.keyboard.press('Backspace'); await c.type(val); };
	const connecter = async (code = '') => {
		await remplir('input[name=Email]', A);
		await remplir('input[type=password]', MDP);
		code && await p.$('input[name=totp_code]') && await remplir('input[name=totp_code]', code);
		const r = reponseLogin();
		await p.keyboard.press('Enter');
		return r;
	};
	const fermerIdentite = () => p.evaluate(() => { const d = [...document.querySelectorAll('dialog[open]')].find(x => /identit/i.test(x.textContent || '')); if (!d) return; const i = d.querySelector('input[type=text], input:not([type])'); if (i) { i.value = 'Essai'; i.dispatchEvent(new Event('input', { bubbles: true })); } const b = [...d.querySelectorAll('button')].find(x => /Enregistrer|Save/i.test(x.textContent || '')); b && b.click(); });
	// After saving the identity, wait until no dialog is shown any more (the save takes a moment; leaving
	// before it ends asks "close this window?").
	const sansFenetre = () => p.waitForFunction(() => ![...document.querySelectorAll('dialog')].some(d => d.open || 'none' !== getComputedStyle(d).display && d.getBoundingClientRect().height > 0), { timeout: 15000 }).catch(() => {});
	const authentifie = () => p.waitForFunction(() => true === (window.rl && rl.settings && rl.settings.get('Auth')), { timeout: 60000 });
	const reglages = async () => {
		await p.evaluate(() => { location.hash = '#/settings/two-factor-auth'; });
		await p.waitForSelector('.b-settings-two-factor', { visible: true, timeout: 30000 }).catch(() => {});
		await pause(1500);
	};
	// A dialog still closing can cover a button: wait until it is the element under its own centre.
	const auPremierPlan = sel => p.waitForFunction(s => { const e = document.querySelector(s); if (!e || !e.offsetParent) return false; e.scrollIntoView({ block: 'center' }); const r = e.getBoundingClientRect(); const x = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2); return !!x && (x === e || e.contains(x)); }, { timeout: 15000 }, sel);
	const cliquer = async sel => { await auPremierPlan(sel); await p.click(sel); };
	const visible = sel => p.$eval(sel, e => !!e.offsetParent).catch(() => false);
	const deconnecter = async () => {
		await p.evaluate(() => rl.app.logout());
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 30000 });
	};

	try {
		// 1. Settings: the section, the masked address.
		await ecranConnexion();
		const j0 = await connecter();
		verifier(!!j0.Result, 'connexion par le mot de passe seul (aucun facteur)');
		await authentifie(); await pause(4000);
		await fermerIdentite(); await sansFenetre();
		await reglages();
		verifier(await visible('.b-settings-two-factor-email'), 'réglages : la section « Code par l\'adresse de secours » est là');
		const masque = await p.$eval('.b-settings-two-factor-email strong[dir=ltr]', e => e.textContent.trim()).catch(() => '');
		verifier('e•••@example.com' === masque, 'l\'adresse vérifiée est montrée masquée (« ' + masque + ' »)');
		await capture('courriel-1-reglages', '.b-settings-two-factor-email');

		// 2. Switch it on: send, type, first factor -> backup codes proven.
		const envoi = await attendre('EmailCodeRequest', () => cliquer('.twofactor-email-send'));
		verifier(envoi.Result && true === envoi.Result.Sent, 'un code est demandé pour l\'activer (Sent)');
		const c1 = await hote('code');
		verifier(/^\d{8}$/.test(c1), 'la file de la console porte un code de 8 chiffres');
		await p.waitForSelector('.twofactor-email-code', { visible: true, timeout: 10000 }).catch(() => {});
		await remplir('.twofactor-email-code', '00000000');
		const faux = await attendre('EmailCodeEnable', () => cliquer('.twofactor-email-enable'));
		verifier(!faux.Result, 'un faux code n\'active rien');
		await remplir('.twofactor-email-code', c1);
		const actif = await attendre('EmailCodeEnable', () => cliquer('.twofactor-email-enable'));
		verifier(actif.Result && true === actif.Result.Pending && true === actif.Result.PendingEmail, 'le bon code : premier facteur, mis en attente avec des codes de secours');
		await pause(1000);
		const secours = await codesAffiches();
		verifier(8 === secours.length, 'huit codes de secours affichés, une fois');
		await cliquer('.twofactor-codes-saved'); await pause(500);
		await remplir('.twofactor-confirm-code', secours[actif.Result.PendingAsk - 1]);
		const prouve = await attendre('ConfirmBackupCodes', () => cliquer('.twofactor-confirm'));
		verifier(prouve.Result && true === prouve.Result.On && true === prouve.Result.EmailOn, 'codes prouvés : le facteur par courriel est actif');
		await pause(800);
		verifier(await visible('.twofactor-email-on'), 'la section dit « Activé »');
		await capture('courriel-2-active', '.b-settings-two-factor-email');

		// 3. Login with a code asked at the login screen.
		await deconnecter();
		await ecranConnexion();
		verifier(await visible('.twofactor-email button'), 'écran de connexion : le bouton « Recevoir un code sur mon adresse de secours » est là');
		// 2.34.1: the code field and the two buttons at the top of the group; 2.34.2: "Forgot password" right under
		// the password field, "Create account" under the sign-in button.
		const place = await p.evaluate(() => {
			const tout = [...document.querySelectorAll('#plugin-Login-BottomControlGroup *')];
			const pos = s => tout.indexOf(document.querySelector('#plugin-Login-BottomControlGroup ' + s));
			const oubli = document.querySelector('.forgot-link'), compte = document.querySelector('.registration-link');
			const mdp = document.querySelector('input[name=Password]')?.closest('.controls');
			const bouton = document.querySelector('.buttonLogin')?.parentElement;
			return { code: pos('input[name=totp_code]'), cle: pos('.twofactor-key'), mail: pos('.twofactor-email'),
				oubli: !!oubli && oubli.previousElementSibling === mdp, compte: !!compte && compte.previousElementSibling === bouton,
				vide: document.querySelectorAll('#plugin-Login-BottomControlGroup .clearfix:empty').length };
		});
		verifier(place.code >= 0 && place.cle > place.code && place.mail > place.cle,
			'le code, la clé et le courriel en haut du groupe (' + JSON.stringify(place) + ')');
		verifier(place.oubli, '« Mot de passe oublié » juste sous le champ du mot de passe');
		verifier(place.compte, '« Créer un compte » sous le bouton « Se connecter »');
		verifier(0 === place.vide, 'aucune enveloppe vide laissée dans le groupe');
		await remplir('input[name=Email]', A);
		await capture('courriel-3-connexion', 'form');
		const dem = p.waitForResponse(x => /EmailCodeLoginRequest/.test(x.request().postData() || ''), { timeout: 30000 });
		await cliquer('.twofactor-email button');
		await dem; await pause(800);
		const info = await p.evaluate(() => document.body.innerText);
		verifier(/code/i.test(info) && !/example\.com/.test(info), 'la même phrase pour tous, sans l\'adresse de secours');
		verifier(await p.$eval('.twofactor-email button', b => b.disabled).catch(() => false), 'le bouton attend une minute avant une nouvelle demande');
		const c2 = await hote('code');
		verifier(/^\d{8}$/.test(c2) && c2 !== c1, 'un nouveau code part vers la console');
		const jf = await connecter('00000000');
		verifier(!jf.Result && 102 === jf.code, 'un faux code de 8 chiffres est refusé (code ' + jf.code + ')');
		await ecranConnexion();
		const jb = await connecter(c2);
		verifier(!!jb.Result, 'le bon code avec le mot de passe ouvre la session');
		await authentifie().catch(() => {});
		verifier(true === await p.evaluate(() => rl.settings.get('Auth')), 'connecté');

		// 4. The domain turns the code off (two-factor-auth 2.34.0).
		await deconnecter();
		verifier('ok' === await hote('eteindre'), 'le domaine éteint le code par l\'adresse de secours');
		await ecranConnexion();
		await remplir('input[name=Email]', A);
		const dem2 = p.waitForResponse(x => /EmailCodeLoginRequest/.test(x.request().postData() || ''), { timeout: 30000 });
		await cliquer('.twofactor-email button');
		const r2 = await (await dem2).json();
		verifier(true === r2.Result, '… la demande reçoit la même réponse');
		verifier('aucun' === await hote('code'), '… et aucun code n\'est mis dans la file');
		const jc = await connecter(secours[(actif.Result.PendingAsk) % 8]);
		verifier(!!jc.Result, 'un code de secours ouvre toujours le compte');
		await authentifie().catch(() => {}); await pause(3000); await fermerIdentite(); await sansFenetre();
		await reglages();
		verifier(!(await visible('.b-settings-two-factor-email')), 'la section n\'est plus proposée dans les réglages');
		await deconnecter();
		verifier(0 === erreurs.length, 'aucune erreur JavaScript' + (erreurs.length ? ' : ' + erreurs.slice(0, 2).join(' | ') : ''));
	} catch (e) {
		verifier(false, 'exception : ' + (e && e.message || e));
	} finally {
		fs.writeFileSync('/essai/two-factor-auth/etape', 'fin');
		await nav.close();
	}
	console.log('\n' + (n - echecs.length) + '/' + n + ' — ' + (echecs.length ? echecs.length + ' échec(s)' : 'tout est vert'));
	process.exit(echecs.length ? 1 : 0);
})();
