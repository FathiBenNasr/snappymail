'use strict';
// S-19 (audit 2026-10) : plainToHtml() ne doit jamais laisser un « " » du texte
// refermer l'attribut href. On éprouve la vraie source (dev/Common/Html.js),
// chargée dans un bac à sable vm avec ses trois imports bouchonnés, et, si
// JS_DIR désigne un dossier static/js patché par securite/html-js.py, la chaîne
// de remplacements des deux fichiers compilés.
//   node --test securite/plain-to-html.test.js
//   JS_DIR=<copie de static/js> node --test securite/plain-to-html.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = path.join(__dirname, '..', 'dev', 'Common', 'Html.js');
const dossier = process.env.JS_DIR;

// Messages hostiles d'abord.
const ABUS = [
	'"style=position:fixed;inset:0;width:100%;height:100%"@evil.exemple',
	'x\n"onmouseover=alert(1)"@evil.exemple',
	'https://ex"style=position:fixed;inset:0/',
	'voir https://a"b"c/ et "x=y"@z.tn',
];
const SAINS = ['ahmed@bank.tn', 'https://exemple.tn/a?b=c&d=e', '"jean.dupont"@x.tn', 'tel:+21671000000'];

// Toute ancre produite n'a que href (et target) : rien d'autre ne s'y glisse.
function ancresSaines(html) {
	const ancres = html.match(/<a\b[^>]*>/g) || [];
	for (const a of ancres) {
		assert.match(a, /^<a href="[^"]*"( target="_blank")?>$/, `ancre forgée : ${a}`);
	}
	return ancres.length;
}

function chargerSource() {
	let src = fs.readFileSync(SOURCE, 'utf8')
		.replace(/^import .*$/gm, '')
		.replace(/^export const/m, 'const');
	const tmpl = { innerHTML: '', content: { querySelectorAll: () => [] } };
	const sandbox = {
		rl: {},
		createElement: () => tmpl,
		forEachObjectEntry: (o, f) => Object.entries(o).forEach(([k, v]) => f(k, v)),
		isArray: Array.isArray,
		pInt: v => parseInt(v, 10) || 0,
		SettingsUserStore: new Proxy({}, { get: () => () => false }),
		TurndownService: function () { this.addRule = () => this; this.use = () => this; },
		URL, decodeURIComponent, atob, console,
	};
	vm.runInNewContext(src, sandbox, { filename: SOURCE });
	return sandbox.rl.Utils.plainToHtml;
}

test('source : un guillemet ne sort pas de href', () => {
	const plainToHtml = chargerSource();
	for (const texte of ABUS) {
		ancresSaines(plainToHtml(texte));
	}
	// Le cas du rapport, mot pour mot : aucun attribut style posé sur l'ancre.
	const html = plainToHtml(ABUS[0]);
	assert.ok(!/<a [^>]*\sstyle=/.test(html.replace(/href="[^"]*"/g, '')), html);
});

test('source : les liens ordinaires restent des liens', () => {
	const plainToHtml = chargerSource();
	for (const texte of SAINS) {
		assert.ok(ancresSaines(plainToHtml(texte)) >= 1, `plus de lien pour ${texte}`);
	}
	assert.match(plainToHtml('ahmed@bank.tn'), /<a href="mailto:ahmed@bank\.tn">ahmed@bank\.tn<\/a>/);
	// Le guillemet d'une partie locale citée vit encore dans le texte, et en
	// entité dans l'attribut.
	assert.match(plainToHtml('"jean.dupont"@x.tn'), /href="mailto:&quot;jean\.dupont&quot;@x\.tn"/);
});

// Les fichiers compilés : la chaîne .replace(url…).replace(email…), exécutée
// avec les expressions régulières du fichier lui-même.
function chaineCompilee(fichier, re) {
	const s = fs.readFileSync(path.join(dossier, fichier), 'utf8');
	const m = s.match(re);
	assert.ok(m, `chaîne de remplacements absente de ${fichier}`);
	return m;
}

test('app.min.js : un guillemet ne sort pas de href', { skip: !dossier }, () => {
	const s = fs.readFileSync(path.join(dossier, 'min/app.min.js'), 'utf8');
	const url = s.match(/Mt=(\/https\?:[^\n]*?\/gu),/)[1];
	const email = s.match(/Pt=(\/\(\^\|\\r[^\n]*?\/giu),Lt=/)[1];
	const [chaine] = chaineCompilee('min/app.min.js', /\.replace\(Mt,[\s\S]*?\.replace\(Lt,/);
	const f = new Function('Mt', 'Pt', 'Dt', 'x', 'return x' + chaine.replace(/\.replace\(Lt,$/, ''));
	const Mt = eval(url), Pt = eval(email);
	for (const texte of ABUS) {
		ancresSaines(f(Mt, Pt, u => u, texte.replace(/&/g, '&amp;').replace(/>/g, '&gt;').replace(/</g, '&lt;')));
	}
	assert.match(f(Mt, Pt, u => u, 'ahmed@bank.tn'), /mailto:ahmed@bank\.tn">ahmed@bank\.tn</);
});

test('app.js : même chose dans le fichier lisible', { skip: !dossier }, () => {
	const s = fs.readFileSync(path.join(dossier, 'app.js'), 'utf8');
	const [chaine] = chaineCompilee('app.js', /\.replace\(urlRegExp, [\s\S]*?\.replace\(tel,/);
	const urlRegExp = /https?:\/\/[^\p{C}\p{Z}]+[^\p{C}\p{Z}.]/gu;
	const email = eval(s.match(/\temail = (\/\(\^\|\\r.*?\/gui),\n/)[1]);
	const f = new Function('urlRegExp', 'email', 'stripTracking', 'x',
		'return x' + chaine.replace(/\.replace\(tel,$/, ''));
	for (const texte of ABUS) {
		ancresSaines(f(urlRegExp, email, u => u, texte));
	}
});
