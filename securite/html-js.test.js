'use strict';
// La boucle insérée par securite/html-js.py, extraite du fichier patché et
// exécutée contre un faux CSSStyleDeclaration : un url() hors des trois
// propriétés traitées disparaît, le reste demeure.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const dossier = process.env.JS_DIR;

function style(props) {
	const o = Object.keys(props);
	o.getPropertyValue = p => props[p] || '';
	o.removeProperty = p => { delete props[p]; o.splice(o.indexOf(p), 1); };
	o.props = props;
	return o;
}
const cas = () => ({ 'mask-image': 'url(https://evil.example/p.png)', 'border-image-source': 'URL ( //x )',
	'filter': 'url(#f)', 'background-image': 'url(cid:1)', 'color': 'red', 'content': 'url(x)' });
const restants = ['background-image', 'color', 'content'];

test('app.min.js : les url() hors des trois propriétés sont retirés', { skip: !dossier }, () => {
	const s = fs.readFileSync(dossier + '/min/app.min.js', 'utf8');
	const m = s.match(/\(\(\)=>\{for\(let n=r\.length;n--;\)\{.*?\}\}\)\(\)/);
	assert.ok(m, 'boucle absente du fichier minifié');
	const r = style(cas());
	new Function('r', m[0])(r);
	assert.deepStrictEqual(Object.keys(r.props).sort(), restants);
});

test('app.js : même chose dans le fichier lisible', { skip: !dossier }, () => {
	const s = fs.readFileSync(dossier + '/app.js', 'utf8');
	const m = s.match(/for \(let i = oStyle\.length; i--;\) \{[\s\S]*?\n\t+\}\n\t+\}/);
	assert.ok(m, 'boucle absente du fichier lisible');
	const oStyle = style(cas());
	new Function('oStyle', m[0])(oStyle);
	assert.deepStrictEqual(Object.keys(oStyle.props).sort(), restants);
});

test('srcset et sizes ne sont plus dans la liste des attributs permis', { skip: !dossier }, () => {
	assert.ok(!fs.readFileSync(dossier + '/min/app.min.js', 'utf8').includes('"sizes","srcset"'));
	assert.ok(!fs.readFileSync(dossier + '/app.js', 'utf8').includes("'sizes', 'srcset'"));
});
