'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require rpc';
'require dom';

/*
 * A plain LuCI form: Save stages the changes, Save & Apply (here or in
 * LuCI's "Unsaved Changes" dialog) applies them, with LuCI's rollback.
 *
 * A role has two halves, both edited as ordinary staged UCI changes, saved
 * and applied together:
 *  - its matching rules (email, group, sub), the issuer its sub rules belong
 *    to (sub_issuer), and its place in the order: a `role` section of
 *    /etc/config/luci-sso;
 *  - its permissions (read, write: LuCI access groups or patterns): its rpcd
 *    login entry, luci_sso_<role> in /etc/config/rpcd, with the username
 *    sso:<role> and never a password option (luci_sso.rpcd_login). The read
 *    list always grants `unauthenticated`, which the page adds and hides.
 *    The page touches no other rpcd section.
 * LuCI's rollback reverts both files. After an apply, the init script
 * /etc/init.d/luci-sso makes rpcd reload, so open sessions get the new rights.
 *
 * Subject (sub) rules belong to one issuer: a sub identifies an account only
 * at the provider that issued it (OIDC Core §5.7), so the backend counts a
 * role's sub rules only while its sub_issuer equals issuer_url. The role
 * dialog saves sub_issuer with the subjects. The page warns about every role
 * whose sub_issuer is not the Issuer URL, and changes it only when the "Use
 * with this provider" button of that role is pressed.
 */

var callListAclGroups = rpc.declare({
	object: 'luci-sso',
	method: 'list_acl_groups',
	expect: { groups: [] }
});

var callTestConnection = rpc.declare({
	object: 'luci-sso',
	method: 'test_connection',
	params: [ 'issuer_url', 'internal_issuer_url', 'client_id', 'client_secret', 'redirect_uri' ]
});

var callTestConnectionResult = rpc.declare({
	object: 'luci-sso',
	method: 'test_connection_result',
	params: [ 'job' ]
});

/* The connection test runs in the background on the router (see the
 * luci-sso rpcd plugin); the page asks for its result until it is there.
 * The router stops a test after 25 s; the page waits a little longer. */
var TEST_TIMEOUT_MS = 35000;
var TEST_POLL_MS = 500;

/* The provider settings the connection test checks. */
var TEST_FIELDS = [ 'issuer_url', 'internal_issuer_url', 'client_id', 'client_secret', 'redirect_uri' ];

/* Every role's rpcd login entry grants this group in its read list (the page
 * adds it), so the page neither shows it nor lets it be removed. */
var BASELINE = 'unauthenticated';

/* A role name becomes part of the rpcd section name luci_sso_<role>. */
var NAME_MAX = 32;

/* What a read or write list may hold, as luci_sso.rpcd_login checks it. */
var LIST_MAX = 128;
var ENTRY_MAX = 128;

/* The documentation of this release. */
var DOCS = 'https://m00qek.github.io/luci-sso/0.10/';

/* Shown for an empty list. */
var NONE = '\u2014';

/* A list as a table cell's content. The values come from UCI and rpcd, so
 * they are text: LuCI puts a string returned by textvalue into the cell as
 * HTML, but appends the strings of an array as text nodes. */
function renderList(items) {
	if (!items || !items.length) return NONE;
	return E('span', {}, [ items.join(', ') ]);
}

function docLink(path, text) {
	return '<a href="' + DOCS + path + '" target="_blank">' + text + '</a>';
}

/* Why a new role's name cannot be used, or true. */
function checkRoleName(name) {
	if (!/^[A-Za-z0-9_]+$/.test(name))
		return _('Use only letters, digits and underscores.');
	if (name.length > NAME_MAX)
		return _('Use at most %d characters.').format(NAME_MAX);
	if (name === 'default')
		return _('"default" is reserved for the identity provider settings.');
	if (uci.get('luci-sso', name) != null)
		return _('There is already a role with this name.');
	return true;
}

/* Copies text with the Clipboard API, or a selected text area where the
 * API is missing. */
function copyText(text) {
	if (navigator.clipboard && window.isSecureContext)
		return navigator.clipboard.writeText(text);
	return new Promise(function(resolve, reject) {
		var ta = E('textarea', { 'readonly': '', 'aria-hidden': 'true', 'style': 'position:fixed;top:0;left:0;opacity:0' }, [ text ]);
		document.body.appendChild(ta);
		ta.select();
		var ok = false;
		try { ok = document.execCommand('copy'); } catch (e) {}
		document.body.removeChild(ta);
		if (ok) resolve(); else reject(new Error('copy'));
	});
}

/* The roles' matching rules, as the page holds them. */
function roleRules() {
	return uci.sections('luci-sso', 'role').map(function(s) {
		return { name: s['.name'], email: L.toArray(s.email), group: L.toArray(s.group), sub: L.toArray(s.sub) };
	});
}

/* A warning for Scopes: roles match by group, but the scopes do not ask
 * for groups. */
function scopeWarning(scope) {
	var scopes = String(scope || 'openid profile email').trim().split(/\s+/);
	if (scopes.indexOf('groups') >= 0) return null;
	var names = roleRules().filter(function(r) { return r.group.length; }).map(function(r) { return r.name; });
	if (!names.length) return null;
	return _('Roles %h match by group, but Scopes does not ask for <code>groups</code>. Most providers then send no groups, and those rules match nobody.')
		.format(names.join(', '));
}

/* A warning for Require Verified Email: roles that match by email alone. */
function verifiedWarning(on) {
	if (!on) return null;
	var names = roleRules().filter(function(r) { return r.email.length && !r.group.length && !r.sub.length; })
		.map(function(r) { return r.name; });
	if (!names.length) return null;
	return _('Roles %h match by email only. They let a user in only if your identity provider sends <code>email_verified: true</code> for the address; otherwise match those users by group or subject.')
		.format(names.join(', '));
}

/* Fills or empties a warning slot under a field. */
function setWarning(slot, html) {
	if (!slot) return;
	if (html) {
		slot.className = 'alert-message warning luci-sso-warning';
		slot.innerHTML = html;
		slot.removeAttribute('hidden');
	}
	else {
		slot.className = 'luci-sso-warning';
		slot.innerHTML = '';
		slot.setAttribute('hidden', '');
	}
}

function withoutBaseline(list) {
	return L.toArray(list).filter(function(g) { return g !== BASELINE; });
}

/* rpcd's patterns, as luci_sso.rpcd_login reads them: fnmatch(3) without
 * flags, so `*` and `?` are wildcards and `[...]` a character class ([!...]
 * negates). */
function globRegExp(pattern) {
	var out = '^';
	for (var i = 0; i < pattern.length; i++) {
		var ch = pattern.charAt(i);
		if (ch == '*') out += '.*';
		else if (ch == '?') out += '.';
		else if (ch == '[') {
			var j = pattern.indexOf(']', i + 1);
			if (j < i + 2) { out += '\\['; continue; }
			var body = pattern.substring(i + 1, j);
			if (body.charAt(0) == '!') body = '^' + body.substring(1);
			out += '[' + body.replace(/\\/g, '\\\\') + ']';
			i = j;
		}
		else out += ('\\.^$|+(){}]'.indexOf(ch) >= 0) ? '\\' + ch : ch;
	}
	return new RegExp(out + '$');
}

/* The rpcd login entry that holds a role's permissions. */
function entrySection(role) {
	return 'luci_sso_' + role;
}

/* A read list as the entry stores it: as given when it grants BASELINE
 * already, through the name or a pattern such as `*`, and with the name
 * appended otherwise (luci_sso.rpcd_login.with_baseline). */
function withBaselineList(list) {
	var grants = list.some(function(p) {
		var re = null;
		if (p.charAt(0) == '!') return false;
		try { re = globRegExp(p); } catch (e) {}
		return re && re.test(BASELINE);
	});
	return grants ? list : list.concat([ BASELINE ]);
}

/* Stages a role's rpcd login entry, as luci_sso.rpcd_login.stage() writes
 * one: a login named luci_sso_<role>, with the username sso:<role> and no
 * password option, and a read list that grants BASELINE. */
function ensureEntry(role) {
	var sid = entrySection(role);
	if (uci.get('rpcd', sid) == null) {
		uci.add('rpcd', 'login', sid);
		uci.set('rpcd', sid, 'read', [ BASELINE ]);
	}
	if (uci.get('rpcd', sid, 'username') !== 'sso:' + role)
		uci.set('rpcd', sid, 'username', 'sso:' + role);
	if (uci.get('rpcd', sid, 'password') != null)
		uci.unset('rpcd', sid, 'password');
	return sid;
}

/* Why an entry of a read (`read` true) or write list cannot be stored, or
 * true: the checks of luci_sso.rpcd_login, which would otherwise leave the
 * role without an rpcd login entry, so its users could not log in. */
function checkAccessEntry(value, read) {
	if (value.length > ENTRY_MAX)
		return _('Use at most %d characters.').format(ENTRY_MAX);
	if (/[\x00-\x1f\x7f]/.test(value))
		return _('Control characters are not allowed.');
	if (read && value.charAt(0) == '!') {
		var p = value.substring(1).replace(/^\s+/, '');
		var re = null;
		try { re = globRegExp(p); } catch (e) {}
		if (p.length && re && re.test(BASELINE))
			return _('LuCI needs "%s" on every page: it cannot be denied.').format(BASELINE);
	}
	return true;
}

function sleep(ms) {
	return new Promise(function(resolve) { window.setTimeout(resolve, ms); });
}

/* Each check's name, in the order the router runs them. */
function checkTitle(id) {
	switch (id) {
	case 'issuer_https':       return _('Issuer URL');
	case 'discovery':          return _('Discovery');
	case 'issuer_match':       return _('Issuer');
	case 'endpoints':          return _('Endpoints');
	case 'jwks':               return _('Signing keys');
	case 'redirect_uri':       return _('Redirect URI');
	case 'client_credentials': return _('Client credentials');
	default:                   return id;
	}
}

function statusLabel(status) {
	switch (status) {
	case 'pass': return _('Pass');
	case 'fail': return _('Fail');
	case 'warn': return _('Warning');
	default:     return _('Skipped');
	}
}

/* Asks the router for the result of connection test `job` until it is done. */
function awaitTest(job) {
	var deadline = Date.now() + TEST_TIMEOUT_MS;
	var poll = function() {
		return callTestConnectionResult(job).then(function(reply) {
			if (reply && (reply.done || reply.error))
				return reply;
			if (Date.now() > deadline)
				return { error: 'TIMEOUT', message: _('the router did not report a result in time') };
			return sleep(TEST_POLL_MS).then(poll);
		});
	};
	return sleep(TEST_POLL_MS).then(poll);
}

/* The result list of a connection test, one line per check. */
function renderTestResult(reply) {
	if (!reply || reply.error || !Array.isArray(reply.checks))
		return E('div', { 'class': 'alert-message warning luci-sso-test-summary' },
			[ _('The connection test could not run: %s').format((reply && (reply.message || reply.error)) || _('no reply')) ]);

	var counts = { pass: 0, fail: 0, warn: 0, skip: 0 };
	reply.checks.forEach(function(c) { counts[c.status] = (counts[c.status] || 0) + 1; });

	var summary;
	if (counts.fail)
		summary = E('p', { 'class': 'luci-sso-test-summary' }, E('strong', _('%d of %d checks failed. Fix them before you enable SSO.').format(counts.fail, reply.checks.length)));
	else if (counts.warn)
		summary = E('p', { 'class': 'luci-sso-test-summary' }, E('strong', _('No check failed, but some could not be confirmed.')));
	else
		summary = E('p', { 'class': 'luci-sso-test-summary' }, E('strong', _('All checks passed.')));

	return E('div', {}, [
		summary,
		E('ul', { 'class': 'luci-sso-test-results' }, reply.checks.map(function(c) {
			return E('li', { 'class': 'luci-sso-check', 'data-check': c.id, 'data-status': c.status }, [
				E('strong', { 'class': 'luci-sso-check-status' }, '[' + statusLabel(c.status) + ']'), ' ',
				E('span', { 'class': 'luci-sso-check-title' }, [ checkTitle(c.id) ]), ': ',
				/* The router's message quotes the provider's own values:
				 * text, never markup. */
				E('span', { 'class': 'luci-sso-check-message' }, [ c.message ])
			]);
		}))
	]);
}

/* The roles whose sub rules are ignored at a login with Issuer URL `issuer`:
 * those with a subject whose sub_issuer is not exactly it, as the page
 * holds them, with what they were made for. */
function subMismatches(issuer) {
	return uci.sections('luci-sso', 'role').filter(function(s) {
		return L.toArray(s.sub).length > 0 && (s.sub_issuer || '') !== issuer;
	}).map(function(s) {
		return { name: s['.name'], owner: s.sub_issuer || null };
	});
}

return view.extend({
	load: function() {
		return Promise.all([
			callListAclGroups().catch(function() { return null; }),
			uci.load([ 'luci-sso', 'rpcd' ])
		]);
	},

	/* The Read access / Write access cell of a role, from its rpcd login
	 * entry as the page holds it. */
	accessCell: function(name, list) {
		var sid = entrySection(name);
		if (uci.get('rpcd', sid) == null)
			return list == 'read'
				? E('em', { 'class': 'luci-sso-no-entry' }, _('Not set: edit this role and Save & Apply, or its users cannot log in'))
				: NONE;
		var read = withoutBaseline(uci.get('rpcd', sid, 'read'));
		var write = L.toArray(uci.get('rpcd', sid, 'write'));
		if (list == 'read' && !read.length && !write.length)
			return E('em', { 'class': 'luci-sso-no-access' }, _('None: this role grants no access'));
		var items = (list == 'read') ? read : write;
		if (items.length == 1 && items[0] === '*')
			return E('span', { 'title': '*' }, (list == 'read') ? _('Everything') : _('Full admin'));
		return renderList(items);
	},

	/* Checks the provider settings as the form holds them, saved or not. */
	handleTestConnection: function(section_id, output, ev) {
		var m = this._map;
		var params = TEST_FIELDS.map(function(name) {
			var opt = m.lookupOption(name, section_id);
			var v = opt ? opt[0].formvalue(section_id) : null;
			return (v == null) ? '' : String(v);
		});

		dom.content(output, E('p', { 'class': 'spinning' }, _('Testing the connection to the identity provider…')));

		return callTestConnection.apply(null, params).then(function(reply) {
			if (!reply || reply.error)
				return reply || { error: 'NO_REPLY' };
			return awaitTest(reply.job);
		}).catch(function(e) {
			return { error: 'RPC_FAILED', message: e.message };
		}).then(function(reply) {
			dom.content(output, renderTestResult(reply));
		});
	},

	/* Fills a subject-rule slot for the Issuer URL `issuer`: one warning per
	 * role whose sub rules belong to another issuer, each with a button that
	 * stages sub_issuer = `issuer` for that role only, at once, as a Save
	 * would: Save & Apply applies it, the header dialog's Revert discards it. */
	renderSubIssuer: function(slot, issuer) {
		if (!slot)
			return;
		var roles = issuer ? subMismatches(issuer) : [];
		slot.innerHTML = '';
		if (!roles.length) {
			slot.className = 'luci-sso-warning';
			slot.setAttribute('hidden', '');
			return;
		}
		slot.className = 'alert-message warning luci-sso-warning';
		roles.forEach(L.bind(function(r) {
			slot.appendChild(E('p', { 'class': 'luci-sso-sub-mismatch', 'data-role': r.name }, [
				E('span', {}, r.owner
					? _('The subject rules of role <strong>%h</strong> belong to <code>%h</code> and are ignored for <code>%h</code>. A subject identifies one account only at its own provider.').format(r.name, r.owner, issuer)
					: _('The subject rules of role <strong>%h</strong> name no provider (sub_issuer) and are ignored.').format(r.name)),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-action luci-sso-rebind',
					'type': 'button',
					'data-role': r.name,
					'click': ui.createHandlerFn(this, function(ev) {
						uci.set('luci-sso', r.name, 'sub_issuer', issuer);
						return uci.save().then(L.bind(function() {
							this.updateSubIssuer(issuer);
							return ui.changes.init();
						}, this));
					})
				}, [ _('Use with this provider') ])
			]));
		}, this));
		slot.removeAttribute('hidden');
	},

	/* Refreshes every subject-rule slot, and the roles' Subjects cells, for
	 * the Issuer URL in the form. */
	updateSubIssuer: function(issuer) {
		document.querySelectorAll('[data-warning="sub-issuer"]').forEach(L.bind(function(slot) {
			this.renderSubIssuer(slot, issuer);
		}, this));
		var ignored = {};
		subMismatches(issuer).forEach(function(r) { ignored[r.name] = true; });
		document.querySelectorAll('.luci-sso-sub-ignored').forEach(function(el) {
			if (ignored[el.getAttribute('data-role')]) el.removeAttribute('hidden');
			else el.setAttribute('hidden', '');
		});
	},

	render: function(data) {
		var m, s, o;
		var page = this;

		this.aclGroups = Array.isArray(data[0]) ? data[0] : null;

		m = this._map = new form.Map('luci-sso',
			_('Single Sign-On'),
			_('Log in to LuCI with your identity provider, using OpenID Connect (OIDC).'));
		/* The roles' permissions are rpcd login entries: load and save
		 * /etc/config/rpcd with the map. */
		m.chain('rpcd');

		/* ------------------------------------------------------------------ */
		/* Identity provider                                                    */
		/* ------------------------------------------------------------------ */
		s = m.section(form.NamedSection, 'default', 'oidc', _('Identity provider'));
		s.addremove = false;
		s.tab('provider', _('Provider'));
		s.tab('advanced', _('Advanced'));

		/* Provider: in the order of setting up. Connect, test, switch on. */
		o = s.taboption('provider', form.Value, 'issuer_url', _('Issuer URL'),
		        _('Your identity provider\'s address, exactly as it identifies itself (its issuer). Must use HTTPS.'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (value && !value.match(/^https:\/\//))
				return _('Must use HTTPS');
			return true;
		};
		o.placeholder = 'https://accounts.google.com';
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var node = form.Value.prototype.renderWidget.apply(this, [ section_id, option_index, cfgvalue ]);
			var slot = E('div', { 'class': 'luci-sso-warning', 'data-warning': 'sub-issuer', 'hidden': '' });
			page.renderSubIssuer(slot, (cfgvalue != null) ? String(cfgvalue) : (uci.get('luci-sso', section_id, 'issuer_url') || ''));
			return E('div', {}, [ node, slot ]);
		};
		o.onchange = function(ev, section_id, value) {
			page.updateSubIssuer(String(value || ''));
		};

		o = s.taboption('provider', form.Value, 'client_id', _('Client ID'),
		        _('From the client (application) you created for this router at your identity provider.'));
		o.rmempty = false;

		o = s.taboption('provider', form.Value, 'client_secret', _('Client Secret'),
		        _('From the same client.'));
		o.password = true;
		o.rmempty = false;

		o = s.taboption('provider', form.Value, 'redirect_uri', _('Redirect URI'),
		        _('Register this exact address with your identity provider. Must use HTTPS.'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (value && !value.match(/^https:\/\//))
				return _('Must use HTTPS');
			return true;
		};
		o.cfgvalue = function(section_id) {
			var val = uci.get('luci-sso', section_id, 'redirect_uri');
			if (!val)
				return 'https://' + window.location.hostname + '/cgi-bin/luci-sso/callback';
			return val;
		};
		/* The widget shows the suggestion cfgvalue returns, so on an untouched
		 * save formvalue equals cfgvalue and LuCI's form.save() would skip the
		 * write, leaving redirect_uri unset. forcewrite persists it regardless. */
		o.forcewrite = true;
		/* Shown in full, with a Copy button: it has to be pasted into the
		 * identity provider exactly. */
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var node = form.Value.prototype.renderWidget.apply(this, [ section_id, option_index, cfgvalue ]);
			var input = node.querySelector('input');
			/* Wide enough for the whole address; layout only, the theme's
			 * look is kept. */
			node.style.maxWidth = '100%';
			if (input) {
				input.style.width = '34em';
				input.style.maxWidth = '100%';
			}
			var status = E('span', { 'class': 'luci-sso-copy-status', 'aria-live': 'polite' });
			var btn = E('button', {
				'class': 'cbi-button cbi-button-neutral luci-sso-copy',
				'type': 'button',
				'title': _('Copy the Redirect URI'),
				'click': function(ev) {
					ev.preventDefault();
					return copyText(input ? input.value : '').then(function() {
						status.textContent = _('Copied');
					}, function() {
						status.textContent = _('Could not copy: select the address and copy it by hand.');
					}).then(function() {
						window.setTimeout(function() { status.textContent = ''; }, 3000);
					});
				}
			}, _('Copy'));
			return E('div', { 'class': 'control-group luci-sso-redirect' }, [ node, btn, ' ', status ]);
		};

		o = s.taboption('provider', form.Value, 'scope', _('Scopes'),
		        _('What the router asks your identity provider to send, separated by spaces. Add <code>groups</code> if roles match by group.'));
		o.placeholder = 'openid profile email';
		o.rmempty = true;
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var node = form.Value.prototype.renderWidget.apply(this, [ section_id, option_index, cfgvalue ]);
			var slot = E('div', { 'class': 'luci-sso-warning', 'data-warning': 'scope', 'hidden': '' });
			setWarning(slot, scopeWarning(cfgvalue != null ? cfgvalue : uci.get('luci-sso', section_id, 'scope')));
			return E('div', {}, [ node, slot ]);
		};
		o.onchange = function(ev, section_id, value) {
			setWarning(document.querySelector('[data-warning="scope"]'), scopeWarning(value));
		};

		o = s.taboption('provider', form.DummyValue, '_test_connection', _('Test Connection'),
		        _('Checks the values in this form, including unsaved changes, against the identity provider: ' +
		          'discovery, the issuer, the signing keys, the Redirect URI, and the Client ID and secret. ' +
		          'Nothing is saved, and it works before SSO is enabled. See %s.')
		            .format(docLink('how-to/sysadmin/configure-in-luci/#3-test-the-connection', _('testing the connection'))));
		o.renderWidget = function(section_id) {
			var output = E('div', { 'class': 'luci-sso-test-output', 'aria-live': 'polite' });
			return E('div', {}, [
				E('button', {
					'class': 'cbi-button cbi-button-action',
					'type': 'button',
					'id': 'luci-sso-test-connection',
					'click': ui.createHandlerFn(page, 'handleTestConnection', section_id, output)
				}, _('Test connection')),
				output
			]);
		};

		o = s.taboption('provider', form.Flag, 'enabled', _('Enable SSO'),
		        _('Shows the SSO button on the LuCI login page. Test the connection first. Password login keeps working either way.'));
		o.rmempty = false;

		/* Advanced */
		o = s.taboption('advanced', form.Flag, 'require_email_verified', _('Require Verified Email'),
		        _('Match a user by email address only if the identity provider says it has checked the address (<code>email_verified</code>). ' +
		          'Groups and subjects are not affected. See %s.')
		            .format(docLink('explanation/roles-and-permissions/#verified-email-addresses', _('verified email addresses'))));
		/* On when the option is unset, as the backend treats it. */
		o.default = o.enabled;
		o.rmempty = false;
		o.renderWidget = function(section_id, option_index, cfgvalue) {
			var node = form.Flag.prototype.renderWidget.apply(this, [ section_id, option_index, cfgvalue ]);
			var on = ((cfgvalue != null) ? cfgvalue : this.default) == this.enabled;
			var slot = E('div', { 'class': 'luci-sso-warning', 'data-warning': 'verified', 'hidden': '' });
			setWarning(slot, verifiedWarning(on));
			return E('div', {}, [ node, slot ]);
		};
		o.onchange = function(ev, section_id, value) {
			setWarning(document.querySelector('[data-warning="verified"]'), verifiedWarning(value == this.enabled));
		};

		o = s.taboption('advanced', form.Value, 'clock_tolerance', _('Clock Tolerance'),
		        _('How far the router\'s clock may differ from the provider\'s, in seconds (0–3600).'));
		o.datatype = 'range(0,3600)';
		o.default = '60';
		o.placeholder = '60';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'internal_issuer_url', _('Internal Issuer URL'),
		        _('Only if the router must reach the provider at a different address than your browser does. ' +
		          'An address such as <code>https://10.0.0.5:8443</code>, with no path. Leave it empty otherwise. See %s.')
		            .format(docLink('how-to/sysadmin/split-horizon/', _('split-horizon networking'))));
		o.optional = true;
		o.rmempty = true;
		o.validate = function(section_id, value) {
			if (value && !value.match(/^https:\/\//))
				return _('Must use HTTPS');
			return true;
		};
		o.placeholder = 'https://' + window.location.hostname + ':8443';

		o = s.taboption('advanced', form.DynamicList, 'trusted_proxy', _('Trusted Proxy'),
		        _('Only if LuCI sits behind a reverse proxy on this address. Requests from it skip luci-sso\'s per-client limits, so the proxy must limit clients itself. See %s.')
		            .format(docLink('how-to/sysadmin/reverse-proxy/', _('running LuCI behind a reverse proxy'))));
		/* What the backend accepts: an IPv4 or IPv6 address, or a range with
		 * a prefix length. No netmask, port or zone. */
		o.datatype = 'or(ipaddr("nomask"),cidr)';
		o.optional = true;
		o.rmempty = true;
		o.placeholder = '127.0.0.1';

		/* ------------------------------------------------------------------ */
		/* Roles                                                                */
		/* ------------------------------------------------------------------ */
		s = m.section(form.GridSection, 'role', _('Roles'),
			_('Who can log in, and what they can do. A user gets the first role, from the top, that matches; drag rows to reorder.') + '<br />' +
			_('Changes take effect with Save &amp; Apply.'));
		s.addremove = true;
		s.anonymous = false;
		s.sortable = true;
		s.modaledit = true;
		s.nodescriptions = true;
		s.modaltitle = function(section_id) {
			return _('Role: %h').format(section_id);
		};
		s.handleAdd = function(ev, name) {
			var ok = checkRoleName(name ? name.trim() : '');
			if (ok !== true) {
				ui.addNotification(null, E('p', {}, ok), 'danger');
				return;
			}
			return form.GridSection.prototype.handleAdd.call(this, ev, name.trim());
		};
		/* Deleting a role deletes its rpcd login entry with it. */
		s.handleRemove = function(section_id, ev) {
			if (uci.get('rpcd', entrySection(section_id)) != null)
				uci.remove('rpcd', entrySection(section_id));
			return form.GridSection.prototype.handleRemove.call(this, section_id, ev);
		};
		/* The Add box: a placeholder, and the role name rules checked as you
		 * type, with the reason next to the box. */
		s.renderSectionAdd = function(extra_class) {
			var el = form.GridSection.prototype.renderSectionAdd.apply(this, [ extra_class ]);
			var input = el.querySelector('.cbi-section-create-name');
			var button = el.querySelector('.cbi-button-add');
			if (!input || !button)
				return el;
			var msg = E('div', { 'class': 'cbi-value-description luci-sso-name-error', 'aria-live': 'polite' });
			input.setAttribute('placeholder', _('New role name, e.g. viewers'));
			input.setAttribute('aria-label', _('New role name'));
			var check = function() {
				var v = input.value.trim();
				var ok = (v === '') ? true : checkRoleName(v);
				msg.textContent = (ok === true) ? '' : ok;
				input.classList.toggle('cbi-input-invalid', ok !== true);
				button.disabled = (v === '' || ok !== true) ? true : null;
			};
			input.addEventListener('keyup', check);
			input.addEventListener('blur', check);
			input.addEventListener('input', check);
			el.appendChild(msg);
			return el;
		};
		/* The subject-rule warning, above the table as well. */
		s.renderContents = function(cfgsections, nodes) {
			var el = form.GridSection.prototype.renderContents.apply(this, [ cfgsections, nodes ]);
			var slot = E('div', { 'class': 'luci-sso-warning', 'data-warning': 'sub-issuer', 'hidden': '' });
			page.renderSubIssuer(slot, uci.get('luci-sso', 'default', 'issuer_url') || '');
			var descr = el.querySelector('.cbi-section-descr');
			if (descr)
				descr.parentNode.insertBefore(slot, descr.nextSibling);
			else
				el.insertBefore(slot, el.firstChild);
			return el;
		};
		/* --- Table columns (visible inline) --- */
		var column = function(name, title, option) {
			o = s.option(form.DummyValue, name, title);
			o.modalonly = false;
			o.textvalue = function(section_id) {
				return renderList(L.toArray(uci.get('luci-sso', section_id, option)));
			};
		};
		column('_emails', _('Emails'), 'email');
		column('_groups', _('Groups'), 'group');

		/* Subjects, marked when they are ignored (see subMismatches). */
		o = s.option(form.DummyValue, '_subs', _('Subjects'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			var subs = L.toArray(uci.get('luci-sso', section_id, 'sub'));
			if (!subs.length)
				return NONE;
			var ignored = subMismatches(uci.get('luci-sso', 'default', 'issuer_url') || '')
				.some(function(r) { return r.name == section_id; });
			return E('span', {}, [
				E('span', {}, [ subs.join(', ') ]), ' ',
				E('em', { 'class': 'luci-sso-sub-ignored', 'data-role': section_id, 'hidden': ignored ? null : '' },
					_('(ignored: another provider)'))
			]);
		};

		o = s.option(form.DummyValue, '_read', _('Read access'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return page.accessCell(section_id, 'read');
		};

		o = s.option(form.DummyValue, '_write', _('Write access'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return page.accessCell(section_id, 'write');
		};

		/* --- Modal fields (edit popup only) --- */
		o = s.option(form.DynamicList, 'email', _('Emails'),
			_('Users whose email address is one of these. Letter case is ignored. ' +
			  'While Require Verified Email is on, the provider must mark the address as verified.'));
		o.modalonly = true;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'group', _('Groups'),
			_('Users in one of these groups, from the provider\'s <code>groups</code> claim. Letter case matters. ' +
			  'Needs <code>groups</code> in Scopes.'));
		o.modalonly = true;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'sub', _('Subjects'),
			_('Users whose account identifier, the OIDC <code>sub</code> claim, is one of these. It never changes, unlike an email address. ' +
			  'Compared exactly, including letter case. A user who is refused sees their own identifier on the error page. See %s.')
			    .format(docLink('explanation/roles-and-permissions/#matching-by-subject', _('matching by subject'))));
		o.modalonly = true;
		o.rmempty = true;

		/* Saved with the subjects, by the same dialog Save, so they are
		 * applied together. A role's first subject gets the Issuer URL. */
		var subsInForm = function(opt, section_id) {
			return L.toArray(opt.section.formvalue(section_id, 'sub')).filter(function(v) { return v !== ''; });
		};
		o = s.option(form.Value, 'sub_issuer', _('Subject issuer'),
			_('The identity provider the subjects belong to. They count only while this is exactly the Issuer URL: a subject identifies one account only at its own provider. ' +
			  'Filled in with the Issuer URL when the role gets its first subject.'));
		o.modalonly = true;
		o.rmempty = true;
		o.forcewrite = true;
		o.load = function(section_id) {
			var v = uci.get('luci-sso', section_id, 'sub_issuer');
			if (v)
				return v;
			if (L.toArray(uci.get('luci-sso', section_id, 'sub')).length)
				return null;
			return uci.get('luci-sso', 'default', 'issuer_url') || null;
		};
		o.validate = function(section_id, value) {
			if (value && !value.match(/^https:\/\//))
				return _('Must use HTTPS');
			if (!value && subsInForm(this, section_id).length)
				return _('Needed for the subjects: the Issuer URL they belong to.');
			return true;
		};
		o.write = function(section_id, value) {
			if (!subsInForm(this, section_id).length)
				return this.remove(section_id);
			if (uci.get('luci-sso', section_id, 'sub_issuer') !== value)
				uci.set('luci-sso', section_id, 'sub_issuer', value);
		};
		o.remove = function(section_id) {
			if (uci.get('luci-sso', section_id, 'sub_issuer') != null)
				uci.unset('luci-sso', section_id, 'sub_issuer');
		};

		/* Read and write access: the lists of the role's rpcd login entry,
		 * luci_sso_<role>, staged with the role's other options. Saving the
		 * dialog always leaves the role with an entry. The router's access
		 * groups are offered as suggestions; any name or pattern can be typed.
		 * `unauthenticated` is never shown, and always kept in the read list. */
		var accessOption = function(list, title, description, everything) {
			o = s.option(form.DynamicList, list, title, description);
			o.modalonly = true;
			o.rmempty = true;
			o.placeholder = _('-- choose or type a group --');
			if (page.aclGroups) {
				o.value('*', everything);
				page.aclGroups.forEach(function(g) {
					if (g !== BASELINE) o.value(g);
				});
			}
			o.validate = function(section_id, value) {
				var all = L.toArray(this.formvalue(section_id));
				if (all.length > LIST_MAX)
					return _('Use at most %d entries.').format(LIST_MAX);
				return (value == null || value === '') ? true : checkAccessEntry(String(value), list == 'read');
			};
			o.load = function(section_id) {
				var v = L.toArray(uci.get('rpcd', entrySection(section_id), list));
				return (list == 'read') ? withoutBaseline(v) : v;
			};
			o.write = function(section_id, value) {
				var sid = ensureEntry(section_id);
				var next = L.toArray(value);
				if (list == 'read')
					next = withBaselineList(next);
				if (L.toArray(uci.get('rpcd', sid, list)).join('\n') !== next.join('\n'))
					uci.set('rpcd', sid, list, next);
			};
			o.remove = function(section_id) {
				var sid = ensureEntry(section_id);
				if (list == 'read') {
					/* Nothing listed: the read list grants `unauthenticated`
					 * alone. */
					var cur = L.toArray(uci.get('rpcd', sid, 'read'));
					if (cur.length != 1 || cur[0] !== BASELINE)
						uci.set('rpcd', sid, 'read', [ BASELINE ]);
				}
				else if (uci.get('rpcd', sid, 'write') != null) {
					uci.unset('rpcd', sid, 'write');
				}
			};
			return o;
		};

		accessOption('read', _('Read access'),
			_('LuCI access groups the role can see. <code>*</code> is everything. Patterns such as <code>luci-mod-status-*</code> work too. ' +
			  '<code>unauthenticated</code> is always included, since LuCI needs it on every page, and is not listed here. ' +
			  'With nothing here, the role\'s users can log in but see nothing.'),
			_('* (everything)'));

		accessOption('write', _('Write access'),
			_('LuCI access groups the role can change; changing includes seeing. Include <code>luci-base</code> to save settings. ' +
			  '<code>*</code> makes the role a full admin.'),
			_('* (full admin)'));

		return m.render();
	}
});
