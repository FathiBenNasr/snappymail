/**
 * two-factor-auth 2.30.0 — the code is judged BEFORE the password reaches the
 * directory, end to end on banc-smail: real Cyrus, real directory (o=sky and
 * its password policy), an ephemeral account. Nothing on production.
 *
 * The proof is the directory's own count. At each checkpoint this script
 * writes /essai/two-factor-auth/etape (a name), and preparer.sh, on the host,
 * answers in /essai/two-factor-auth/lu with the number of pwdFailureTime
 * values of the account — the failures the policy counted.
 *
 * Phases:
 *  1. password alone (no second factor yet): session; the TOTP is enrolled
 *     through the plugin's actions; logout.                       -> checkpoint
 *  2. three logins that must stop before the directory: right password +
 *     wrong code, wrong password + no code, wrong password + wrong code. Same
 *     message as a wrong password, the reminder under it when the field is
 *     empty, and each as long as Cyrus' failedloginpause.         -> checkpoint
 *  3. control: wrong password + RIGHT code — the code passes, the password
 *     reaches the directory and fails: the count must rise by one, or the
 *     measure would prove nothing.                                -> checkpoint
 *  4. right password + a fresh code: the session opens.
 *
 * Environment: A (address), MDP (password), BASE, CAPTURES=dir.
 * Run through BANC=avant sh preparer.sh.
 */
const puppeteer = require('/app/scripts/node_modules/puppeteer');
const crypto = require('crypto');
const fs = require('fs');
const BASE = process.env.BASE || 'http://10.89.10.1:8932';
const A = process.env.A, MDP = process.env.MDP;
const CAPTURES = process.env.CAPTURES || '';
const ICI = '/essai/two-factor-auth';
const pause = ms => new Promise(r => setTimeout(r, ms));
const echecs = []; let n = 0;
const verifier = (ok, quoi) => { n++; if (!ok) echecs.push(quoi); console.log((ok ? 'ok   ' : 'ÉCHEC ') + quoi); };

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
const attendrePasNeuf = async dernier => { while (pasCourant() <= dernier) await pause(1000); return pasCourant(); };
// A code that is none of the three the server accepts (previous, current, next step).
const codeFaux = s => { const ok = [-1, 0, 1].map(d => totp(s, pasCourant() + d)); let c = 0; while (ok.includes(String(c).padStart(6, '0'))) c++; return String(c).padStart(6, '0'); };

/** Asks the host how many failures the directory counted for the account. */
const echecsAnnuaire = async etape => {
	try { fs.unlinkSync(ICI + '/lu'); } catch (e) {}
	fs.writeFileSync(ICI + '/etape', etape);
	for (let i = 0; i < 120; i++) {
		await pause(500);
		try { const s = fs.readFileSync(ICI + '/lu', 'utf8').trim(); if (/^\d+$/.test(s)) return +s; } catch (e) {}
	}
	return null;
};

(async () => {
	const nav = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', args: ['--no-sandbox', '--disable-dev-shm-usage'] });
	const p = await nav.newPage();
	const erreurs = []; p.on('pageerror', e => erreurs.push(e.message));
	p.on('dialog', d => d.dismiss().catch(() => {}));
	await p.setUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36');
	await p.setViewport({ width: 1280, height: 900 });
	const json = (action, prm = {}) => p.evaluate((action, prm) => new Promise(r =>
		rl.app.Remote.request(action, (err, data) => r({ ok: !!(data && data.Result), res: data && data.Result }), prm)), action, prm);
	// The logout reloads the page by itself: a navigation sent meanwhile is aborted, and retried.
	const aller = async () => {
		for (let i = 0; ; i++) {
			try { await p.goto(BASE + '/', { waitUntil: 'domcontentloaded', timeout: 90000 }); return; }
			catch (e) { if (i >= 3 || !/ERR_ABORTED/.test(e.message)) throw e; await pause(1500); }
		}
	};
	const session = () => p.evaluate(() => true === (window.rl && rl.settings && rl.settings.get('Auth')));

	/** One login through the real form; the answer of DoLogin and how long it took. */
	const connexion = async (mdp, code) => {
		await aller();
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		const champ = await p.$('input[name=Email], input[type=email]');
		await champ.click({ clickCount: 3 }); await champ.type(A);
		await p.type('input[type=password]', mdp);
		if (code) await p.type('input[name=totp_code]', code);
		const reponse = p.waitForResponse(r => 'POST' === r.request().method() && /"Action":"Login"|Action=Login/.test(r.request().postData() || ''), { timeout: 60000 });
		const t0 = Date.now();
		await p.keyboard.press('Enter');
		const r = await reponse;
		const duree = (Date.now() - t0) / 1000;
		let j = {}; try { j = await r.json(); } catch (e) {}
		await pause(800);
		const ecran = await p.evaluate(() => {
			const t = s => (document.querySelector(s) || {}).textContent || '';
			return { erreur: t('#V-Login .alert, .b-login-content .alert') };
		});
		return { ok: !!j.Result, code: j.code, nom: j.messageAdditional || '', duree, ecran: ecran.erreur.replace(/\s+/g, ' ').trim() };
	};

	try {
		/* 1. Enrolment, through the plugin's own actions. */
		await aller();
		await p.waitForSelector('input[type=password]', { visible: true, timeout: 90000 });
		const champ = await p.$('input[name=Email], input[type=email]');
		await champ.click({ clickCount: 3 }); await champ.type(A);
		await p.type('input[type=password]', MDP);
		await p.keyboard.press('Enter');
		await p.waitForFunction(() => true === (window.rl && rl.settings && rl.settings.get('Auth')), { timeout: 60000 });
		await pause(3000);
		const cree = await json('PluginCreateTwoFactorSecret');
		const secret = cree.res && cree.res.Secret;
		verifier(!!secret, 'secret créé');
		let pas = pasCourant();
		verifier((await json('PluginVerifyTwoFactorCode', { Code: totp(secret, pas) })).ok, 'code du téléphone éprouvé');
		verifier((await json('PluginEnableTwoFactor', { Enable: '1' })).ok, 'second facteur activé');
		await json('Logout');
		await pause(2500);
		const n0 = await echecsAnnuaire('inscrit');
		verifier(null !== n0, 'l’hôte lit le compte d’échecs de l’annuaire : ' + n0);

		/* 2. Three logins stopped before the directory. */
		const faux = 'Faux' + MDP.slice(4);
		const cas = [
			['bon mot de passe, code faux', MDP, codeFaux(secret), false],
			['mot de passe faux, sans code', faux, '', true],
			['mot de passe faux, code faux', faux, codeFaux(secret), false]
		];
		for (const [quoi, mdp, code, vide] of cas) {
			const r = await connexion(mdp, code);
			verifier(!r.ok && 102 === r.code && '' === r.nom, quoi + ' : refusé comme un mot de passe faux (code ' + r.code + ', nom « ' + r.nom + ' »)');
			verifier(r.duree >= 2.9, quoi + ' : aussi long qu’un mot de passe faux chez Cyrus (' + r.duree.toFixed(1) + ' s)');
			// 2.32.0: the reminder (code, backup code or key) follows every refusal, code typed or not:
			// the same text whatever the cause, so it says nothing of the account.
			verifier(/deux étapes|2-Step/i.test(r.ecran) && /secours|backup/i.test(r.ecran), quoi + ' : le rappel du code, avec le code de secours, est affiché — « ' + r.ecran.slice(0, 120) + ' »');
			if (vide && CAPTURES) {
				const el = await p.$('#V-Login form, .b-login-content');
				await (el || p).screenshot({ path: CAPTURES + '/avant-1-rappel.png' });
			}
		}
		const n1 = await echecsAnnuaire('refus');
		verifier(n1 === n0, 'aucun de ces trois essais n’a atteint l’annuaire : ' + n0 + ' → ' + n1 + ' échec(s) compté(s)');

		/* 3. Control: the code is right, the password reaches the directory. */
		pas = await attendrePasNeuf(pas);
		const t = await connexion(faux, totp(secret, pas));
		verifier(!t.ok && 102 === t.code, 'témoin, code juste et mot de passe faux : refusé (' + t.duree.toFixed(1) + ' s)');
		const n2 = await echecsAnnuaire('temoin');
		verifier(n2 === n0 + 1, 'témoin : cette fois l’annuaire a compté l’échec (' + n1 + ' → ' + n2 + ') — la mesure voit ce qu’elle doit voir');

		/* 4. The owner. */
		pas = await attendrePasNeuf(pas);
		const b = await connexion(MDP, totp(secret, pas));
		verifier(b.ok, 'bon mot de passe et code neuf : la session s’ouvre');
		await p.waitForFunction(() => true === (window.rl && rl.settings && rl.settings.get('Auth')), { timeout: 30000 }).catch(() => {});
		verifier(await session(), 'session ouverte (Auth)');
		verifier(0 === erreurs.length, 'aucune erreur JavaScript' + (erreurs.length ? ' : ' + erreurs[0].slice(0, 120) : ''));
	} catch (e) {
		verifier(false, 'exception : ' + (e && e.message));
	} finally {
		try { fs.writeFileSync(ICI + '/etape', 'fin'); } catch (e) {}
		await nav.close();
	}
	console.log(`\n${n - echecs.length}/${n} contrôles` + (echecs.length ? ' — ÉCHECS : ' + echecs.join(' | ') : ''));
	process.exit(echecs.length ? 1 : 0);
})();
