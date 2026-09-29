import { Notifications } from 'Common/Enums';
import { MessageSetAction, ComposeType/*, FolderType*/ } from 'Common/EnumsUser';
import { doc, createElement, elementById, dropdowns, dropdownVisibility, SettingsGet, leftPanelDisabled } from 'Common/Globals';
import { plainToHtml } from 'Common/Html';
import { getNotification } from 'Common/Translator';
import { EmailCollectionModel } from 'Model/EmailCollection';
import { MessageUserStore } from 'Stores/User/Message';
import { MessagelistUserStore } from 'Stores/User/Messagelist';
import { SettingsUserStore } from 'Stores/User/Settings';
import * as Local from 'Storage/Client';
import { ThemeStore } from 'Stores/Theme';
import Remote from 'Remote/User/Fetch';
import { attachmentDownload } from 'Common/Links';

import { AccountModel } from 'Model/Account';
import { IdentityModel } from 'Model/Identity';
import { AccountUserStore } from 'Stores/User/Account';
import { IdentityUserStore } from 'Stores/User/Identity';
import { isArray } from 'Common/Utils';

import { showScreenPopup } from 'Knoin/Knoin';
import { IdentityPopupView } from 'View/Popup/Identity';

export const

// 1 = move, 2 = copy
moveAction = ko.observable(0),

dropdownsDetectVisibility = (() =>
	dropdownVisibility(!!dropdowns.find(item => item.classList.contains('show')))
).debounce(50),


editIdentity = Identity => showScreenPopup(IdentityPopupView, [Identity]),

loadAccountsAndIdentities = () => {
	AccountUserStore.loading(true);
	IdentityUserStore.loading(true);

	Remote.request('AccountsAndIdentities', (iError, oData) => {
		AccountUserStore.loading(false);
		IdentityUserStore.loading(false);

		if (!iError) {
			let items = oData.Result.Accounts;
			AccountUserStore(isArray(items)
				? items.map(oValue => new AccountModel(oValue.email, oValue.name))
				: []
			);
			// mainIdentityName is the login identity's display name, resolved by
			// the server against the main account. It cannot be read from
			// IdentityUserStore here, which holds the active account's identities.
			AccountUserStore.unshift(new AccountModel(SettingsGet('mainEmail'),
				SettingsGet('mainAccountName') || SettingsGet('mainIdentityName') || '', false));

			items = oData.Result.Identities;
			IdentityUserStore(isArray(items)
				? items.map(identityData => IdentityModel.reviveFromJson(identityData))
				: []
			);

			// Invoke "Update Identity" pop up right after login
			// https://github.com/the-djmaze/snappymail/issues/1689
			const main = IdentityUserStore.main();
			main && !main.exists() && setTimeout(()=>editIdentity(main), 1000);
		}
	});
},

/**
 * @param {string} link
 * @returns {boolean}
 */
download = (link, name = "") => {
	console.log('download: '+link);
	if (isStandalone()) {
		openRawInNewContext(link, name);
		return;
	}
	// Firefox 98 issue https://github.com/the-djmaze/snappymail/issues/301
	if (ThemeStore.isMobile() || /firefox/i.test(navigator.userAgent)) {
		open(link, '_blank');
		focus();
	} else {
		const oLink = createElement('a', {
			href: link,
			target: '_blank',
			download: name
		});
		doc.body.appendChild(oLink).click();
		oLink.remove();
	}
},

/**
 * Installed as a PWA the app has its own browsing context, so a link opened in
 * a tab lands in the browser instead: a different context, which the browser
 * treats as cross-site. It marks the request Sec-Fetch-Site: cross-site and
 * withholds the SameSite=Strict session cookie. The Raw endpoints work out which
 * account is asking from that cookie, so the tab receives nothing at all and
 * shows a blank page (#81).
 */
isStandalone = () =>
	// Any display mode but "browser" means its own context, and iOS reports it
	// through navigator rather than a media query.
	matchMedia(['standalone', 'minimal-ui', 'fullscreen', 'window-controls-overlay']
		.map(mode => '(display-mode: ' + mode + ')').join(',')).matches
	|| true === navigator.standalone,

isRawLink = href => {
	try {
		const url = new URL(href, location.href);
		return url.origin === location.origin && url.search.includes('/Raw/');
	} catch {
		return false;
	}
},

/**
 * Fetch here, where the cookie still applies, and hand the browser bytes it
 * already has. No second request means nothing for the cookie rules to apply to.
 */
openRawInNewContext = (link, name = '') =>
	rl.fetch(link)
	.then(response => response.ok ? response.blob() : Promise.reject(Error('HTTP ' + response.status)))
	.then(blob => {
		const url = URL.createObjectURL(blob);
		if (name) {
			const oLink = createElement('a', { href: url, download: name });
			doc.body.appendChild(oLink).click();
			oLink.remove();
		} else {
			open(url, '_blank');
			focus();
		}
		// Nothing tells us when the other context is finished with it, so hold it
		// long enough to be opened and let it go rather than leak for the session.
		setTimeout(() => URL.revokeObjectURL(url), 60000);
	})
	.catch(e => {
		console.error(e);
		// Better a tab that reports the real failure than one that silently does
		// nothing, and outside a PWA this is what would have happened anyway.
		open(link, '_blank');
	}),

downloadZip = (name, hashes, onError, fTrigger, folder) => {
	if (hashes.length) {
		let params = {
			target: 'zip',
			filename: name,
			hashes: hashes
		};
		if (!onError) {
			onError = () => alert('Download failed');
		}
		if (folder) {
			params.folder = folder;
//			params.uids = uids;
		}
		Remote.post('AttachmentsActions', fTrigger || null, params)
		.then(result => {
			let hash = result?.Result?.fileHash;
			hash ? download(attachmentDownload(hash), hash+'.zip') : onError();
		})
		.catch(onError);
	}
},

/**
 * @returns {function}
 */
computedPaginatorHelper = (koCurrentPage, koPageCount) => {
	return () => {
		const currentPage = koCurrentPage(),
			pageCount = koPageCount(),
			result = [],
			lang = doc.documentElement.lang,
			fAdd = (index, push = true, customName = '') => {
				const name = index.toLocaleString(lang),
					data = {
						current: index === currentPage,
						name: customName || name,
						title: customName ? name : '',
						value: index
					};

				push ? result.push(data) : result.unshift(data);
			};

		let prev = 0,
			next = 0,
			limit = 2;

		if (1 < pageCount) {
			if (pageCount < currentPage) {
				fAdd(pageCount);
				prev = pageCount;
				next = pageCount;
			} else {
				if (3 >= currentPage || pageCount - 2 <= currentPage) {
					limit += 2;
				}

				fAdd(currentPage);
				prev = currentPage;
				next = currentPage;
			}

			while (0 < limit) {
				--prev;
				++next;

				if (0 < prev) {
					fAdd(prev, false);
					--limit;
				}

				if (pageCount >= next) {
					fAdd(next, true);
					--limit;
				} else if (0 >= prev) {
					break;
				}
			}

			if (3 === prev) {
				fAdd(2, false);
			} else if (3 < prev) {
				fAdd(Math.round((prev - 1) / 2), false, '…');
			}

			if (pageCount - 2 === next) {
				fAdd(pageCount - 1, true);
			} else if (pageCount - 2 > next) {
				fAdd(Math.round((pageCount + next) / 2), true, '…');
			}

			// first and last
			if (1 < prev) {
				fAdd(1, false);
			}

			if (pageCount > next) {
				fAdd(pageCount, true);
			}
		}

		return result;
	};
},

/**
 * @param {string} mailToUrl
 * @returns {boolean}
 */
mailToHelper = mailToUrl => {
	if ('mailto:' === mailToUrl?.slice(0, 7).toLowerCase()) {
		mailToUrl = mailToUrl.slice(7).split('?');

		const
			email = decodeURIComponent(mailToUrl[0]),
			params = new URLSearchParams(mailToUrl[1]),
			to = params.get('to'),
			toEmailModel = value => EmailCollectionModel.fromString(value);

		showMessageComposer([
			ComposeType.Empty,
			null,
			toEmailModel(to ? email + ',' + to : email),
			toEmailModel(params.get('cc')),
			toEmailModel(params.get('bcc')),
			params.get('subject'),
			plainToHtml(params.get('body') || '')
		]);

		return true;
	}

	return false;
},

showMessageComposer = (params = []) =>
{
	rl.app.showMessageComposer(params);
},

setLayoutResizer = (source, sClientSideKeyName, mode) =>
{
	if (source.layoutResizer && source.layoutResizer.mode != mode) {
		source.removeAttribute('style');
	}
	source.observer?.disconnect();
//	source.classList.toggle('resizable', mode);
	if (mode) {
		const length = Local.get(sClientSideKeyName + mode) || SettingsGet('Resizer' + sClientSideKeyName + mode);
		if (length) {
			source.style[mode.toLowerCase()] = length + 'px';
		}
		if (!source.layoutResizer) {
			const resizer = createElement('div', {'class':'resizer'}),
				save = (data => Remote.saveSettings(0, data)).debounce(500),
				size = {},
				store = () => {
					const value = ('Width' == resizer.mode) ? source.offsetWidth : source.offsetHeight,
						prop = resizer.key + resizer.mode;
					(value == Local.get(prop)) || Local.set(prop, value);
					(value == SettingsGet('Resizer' + prop)) || save({['Resizer' + prop]: value});
				},
				cssint = s => {
					let value = getComputedStyle(source, null)[s].replace('px', '');
					if (value.includes('%')) {
						value = source.parentElement['offset'+resizer.mode]
							* value.replace('%', '') / 100;
					}
					return parseFloat(value);
				};
			source.layoutResizer = resizer;
			source.append(resizer);
			resizer.addEventListener('mousedown', {
				handleEvent: function(e) {
					if ('mousedown' == e.type) {
						const lmode = resizer.mode.toLowerCase();
						e.preventDefault();
						size.pos = ('width' == lmode) ? e.pageX : e.pageY;
						size.min = cssint('min-'+lmode);
						size.max = cssint('max-'+lmode);
						size.org = cssint(lmode);
						addEventListener('mousemove', this);
						addEventListener('mouseup', this);
					} else if ('mousemove' == e.type) {
						const lmode = resizer.mode.toLowerCase(),
							length = size.org + (('width' == lmode ? e.pageX : e.pageY) - size.pos);
						if (length >= size.min && length <= size.max ) {
							source.style[lmode] = length + 'px';
							source.observer || store();
						}
					} else if ('mouseup' == e.type) {
						removeEventListener('mousemove', this);
						removeEventListener('mouseup', this);
					}
				}
			});
			source.observer = window.ResizeObserver ? new ResizeObserver(store) : null;
		}
		source.layoutResizer.mode = mode;
		source.layoutResizer.key = sClientSideKeyName;
		source.observer?.observe(source, { box: 'border-box' });
	}
},

viewMessage = (oMessage, popup) => {
	if (popup) {
		oMessage.popupMessage();
	} else {
		MessageUserStore.error('');
		let id = 'rl-msg-' + oMessage.hash,
			body = oMessage.body || elementById(id);
		if (!body) {
			body = createElement('div',{
				id:id,
				hidden:'',
				class:'b-text-part'
					+ (oMessage.pgpSigned() ? ' openpgp-signed' : '')
					+ (oMessage.pgpEncrypted() ? ' openpgp-encrypted' : '')
					+ (oMessage.smimeSigned() ? ' smime-signed' : '')
					+ (oMessage.smimeEncrypted() ? ' smime-encrypted' : '')
			});
			MessageUserStore.purgeCache();
		}

		body.message = oMessage;
		oMessage.body = body;

		if (!SettingsUserStore.viewHTML() || !oMessage.viewHtml()) {
			oMessage.viewPlain();
		}

		MessageUserStore.bodiesDom().append(body);

		MessageUserStore.loading(false);
		oMessage.body.hidden = false;

		if (oMessage.isUnseen() && SettingsUserStore.messageReadAuto()) {
			MessageUserStore.MessageSeenTimer = setTimeout(
				() => MessagelistUserStore.setAction(oMessage.folder, MessageSetAction.SetSeen, [oMessage]),
				SettingsUserStore.messageReadDelay() * 1000 // seconds
			);
		}
	}
},

populateMessageBody = (oMessage, popup) => {
	if (oMessage) {
		popup || MessageUserStore.message(oMessage);
		if (oMessage.body) {
			viewMessage(oMessage, popup);
		} else {
			popup || MessageUserStore.loading(true);
			Remote.message((iError, oData/*, bCached*/) => {
				if (iError) {
					if (Notifications.RequestAborted !== iError && !popup) {
						MessageUserStore.message(null);
						MessageUserStore.error(getNotification(iError));
					}
				} else {
					let json = oData?.Result;
					if (json
						&& ((
								oMessage.hash && oMessage.hash === json.hash
							) || (
								!oMessage.hash
								&& oMessage.folder === json.folder
								&& oMessage.uid == json.uid)
						)
						&& oMessage.revivePropertiesFromJson(json)
					) {
/*
						if (bCached) {
							delete json.flags;
						}
						oMessage.body.remove();
*/
						viewMessage(oMessage, popup);
					}
				}
				popup || MessageUserStore.loading(false);
			}, oMessage.folder, oMessage.uid);
		}
	}
};

leftPanelDisabled.subscribe(value => value && moveAction(0));
moveAction.subscribe(value => value && leftPanelDisabled(false));
