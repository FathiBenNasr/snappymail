#!/usr/bin/env python3
"""Report de Tachyon 7db1e9664 (srcset et url() CSS chargés sans accord) dans le
JavaScript **compilé** de SnappyMail 2.38.2 — app.js et min/app.min.js.

La source (dev/Common/Html.js) porte le même changement dans cette branche ; ce
script l'applique aux fichiers servis, faute de pouvoir reconstruire le paquet
2.38.2 à l'identique. Chaque remplacement doit trouver son ancre **exactement une
fois**, sinon rien n'est écrit.

    python3 securite/html-js.py <dossier static/js> [--verifier]
"""
import sys, os

ANCRES = {
	'app.js': [
		("'hspace', 'sizes', 'srcset', 'vspace',", "'hspace', 'vspace',"),
		("\t\t\t\tif (hasAttribute('color')) {\n\t\t\t\t\toStyle.color = delAttribute('color');\n\t\t\t\t}\n",
		 "\t\t\t\tif (hasAttribute('color')) {\n\t\t\t\t\toStyle.color = delAttribute('color');\n\t\t\t\t}\n\n"
		 "\t\t\t\t// Tachyon 7db1e9664 : url() hors des trois propriétés traitées chargeait sans accord.\n"
		 "\t\t\t\tfor (let i = oStyle.length; i--;) {\n"
		 "\t\t\t\t\tconst property = oStyle[i];\n"
		 "\t\t\t\t\tif (!['background-image', 'list-style-image', 'content'].includes(property)\n"
		 "\t\t\t\t\t && /url\\s*\\(/i.test(oStyle.getPropertyValue(property))) {\n"
		 "\t\t\t\t\t\toStyle.removeProperty(property);\n"
		 "\t\t\t\t\t}\n"
		 "\t\t\t\t}\n"),
	],
	'min/app.min.js': [
		('"hspace","sizes","srcset","vspace",', '"hspace","vspace",'),
		('h("color")&&(r.color=m("color")),!b){',
		 'h("color")&&(r.color=m("color")),(()=>{for(let n=r.length;n--;){const k=r[n];'
		 '["background-image","list-style-image","content"].includes(k)||!/url\\s*\\(/i.test(r.getPropertyValue(k))||r.removeProperty(k)}})(),!b){'),
	],
}

def main():
	base = sys.argv[1]
	verifier = '--verifier' in sys.argv
	resultat = {}
	for nom, paires in ANCRES.items():
		chemin = os.path.join(base, nom)
		s = open(chemin, encoding='utf-8').read()
		for vieux, neuf in paires:
			n_vieux, n_neuf = s.count(vieux), s.count(neuf)
			if n_neuf == 1:
				continue                      # déjà appliqué (le neuf peut contenir l'ancre)
			if n_neuf > 1 or n_vieux != 1:
				sys.exit(f'{nom} : ancre trouvée {n_vieux} fois, rien n\'est écrit')
			s = s.replace(vieux, neuf)
		resultat[chemin] = s
	if verifier:
		for chemin, s in resultat.items():
			if open(chemin, encoding='utf-8').read() != s:
				sys.exit(f'{chemin} : correctif absent')
		print('correctif présent')
		return
	for chemin, s in resultat.items():
		with open(chemin, 'w', encoding='utf-8') as f:
			f.write(s)
		print('écrit', chemin)

main()
