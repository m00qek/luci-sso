'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require rpc';
'require request';
'require dom';

/*
 * One rule: changes take effect with Save & Apply.
 *
 * A role has two halves:
 *  - its matching rules (email, group, sub) and its place in the order: a
 *    `role` section of /etc/config/luci-sso, edited through UCI like any
 *    other LuCI form. Save stages them; Save & Apply applies them;
 *  - its permissions (read, write): the rpcd login entry luci_sso_<role>,
 *    which only the `luci-sso` ubus object may write, and which LuCI's
 *    staged changes cannot hold. The page loads them with list_roles and
 *    keeps edits to them on the page, across a plain Save, until Save &
 *    Apply. Then it writes the roles edited since with set_role, removes the
 *    deleted ones with delete_role, and waits for rpcd to reload with them.
 *    With UCI changes pending, that happens only once LuCI has applied and
 *    confirmed them (its `uci-applied` event): an apply that is rolled back
 *    writes no permissions. With none pending, it happens at once.
 *
 * Subject (sub) rules belong to one issuer: a sub identifies an account only
 * at the provider that issued it (OIDC Core §5.7), so the backend counts them
 * only while the option sub_issuer equals issuer_url. Each save of the form
 * binds them (see bindSubIssuer): to the Issuer URL when they have no issuer
 * yet or already have this one, never silently to a new one. After the
 * Issuer URL changes, the page warns, and only the "Use these subject rules
 * with the new provider" button moves them over.
 */

var callListRoles = rpc.declare({
	object: 'luci-sso',
	method: 'list_roles'
});

var callSetRole = rpc.declare({
	object: 'luci-sso',
	method: 'set_role',
	params: [ 'name', 'read', 'write' ]
});

var callDeleteRole = rpc.declare({
	object: 'luci-sso',
	method: 'delete_role',
	params: [ 'name' ]
});

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

/* Every role's read list grants this group (the ubus object adds it), so the
 * page neither shows it nor lets it be removed. */
var BASELINE = 'unauthenticated';

/* How long to wait for rpcd to reload after a write. The reload takes about
 * two seconds, but uhttpd checks each /ubus/ call's session with a
 * synchronous call to rpcd, for up to half its script timeout (60 s by
 * default), and serves nothing meanwhile. A check that reaches rpcd just as it
 * re-executes itself is never answered, so uhttpd can stall for 30 s; the wait
 * outlasts that rather than report a reload that did finish as failed. */
var RELOAD_TIMEOUT_MS = 45000;
var RELOAD_POLL_MS = 500;

/* A role name becomes part of the rpcd section name luci_sso_<role>. */
var NAME_MAX = 32;

/* LuCI reloads the page this many seconds after it has applied UCI changes;
 * for that one reload, the page sets L.env.apply_display to this, so the
 * reload never comes while the page is open: one day, well under the 2^31-1
 * ms setTimeout takes. See handleSaveApply. */
var HOLD_RELOAD_S = 86400;

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

/* Whether a role has a subject rule, as the page holds the roles. */
function hasSubRules() {
	return roleRules().some(function(r) { return r.sub.length > 0; });
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

/* Whether rpcd still has a reload pending. Asked with a plain request rather
 * than rpc.declare: while rpcd re-executes itself a call can fail, and a
 * failed rpc call can make LuCI report the session as expired. */
function reloadPending() {
	return request.post(rpc.getBaseURL(), {
		jsonrpc: '2.0', id: 1, method: 'call',
		params: [ rpc.getSessionID(), 'luci-sso', 'list_roles', {} ]
	}, { timeout: 2000, nobatch: true, credentials: true }).then(function(res) {
		var msg = res.json();
		var r = (msg && Array.isArray(msg.result)) ? msg.result : null;
		return !(r && r[0] === 0 && r[1] && r[1].reload_pending === false);
	}).catch(function() {
		return true;
	});
}

function awaitReload() {
	var deadline = Date.now() + RELOAD_TIMEOUT_MS;
	var poll = function() {
		return reloadPending().then(function(pending) {
			if (!pending) return true;
			if (Date.now() > deadline) return false;
			return new Promise(function(resolve) {
				window.setTimeout(resolve, RELOAD_POLL_MS);
			}).then(poll);
		});
	};
	/* The reload starts a second after the write. */
	return new Promise(function(resolve) {
		window.setTimeout(resolve, RELOAD_POLL_MS);
	}).then(poll);
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

/* A reply of the luci-sso object: its own errors come back as a result. */
function checkReply(name, reply) {
	if (reply && reply.error)
		throw new Error(_('Role "%s": %s').format(name, reply.message || reply.error));
	return reply;
}

return view.extend({
	load: function() {
		return Promise.all([
			callListRoles().catch(function(e) { return { failed: e }; }),
			callListAclGroups().catch(function() { return null; }),
			uci.load('luci-sso')
		]);
	},

	/* Permissions as rpcd holds them, by role name, and the edits since. */
	loadAccess: function(data) {
		this.accessAvailable = !!(data && Array.isArray(data.roles));
		this.access = {};
		this.edited = {};
		this.deleted = {};
		if (this.accessAvailable)
			data.roles.forEach(L.bind(function(r) {
				this.access[r.name] = { read: L.toArray(r.read), write: L.toArray(r.write) };
			}, this));
	},

	/* A role's permissions: edited, stored, or null when it has no entry. */
	accessOf: function(name) {
		return this.edited[name] || this.access[name] || null;
	},

	/* Records an edit of one list; a role without an entry gets one even
	 * when both lists stay empty. */
	editAccess: function(name, list, value) {
		var cur = this.accessOf(name);
		var shown = function(l) { return (list == 'read' ? withoutBaseline(l) : L.toArray(l)).join('\n'); };
		delete this.deleted[name];
		if (cur && shown(cur[list]) == shown(value))
			return;
		cur = cur || { read: [], write: [] };
		var next = { read: cur.read, write: cur.write };
		next[list] = L.toArray(value);
		this.edited[name] = next;
	},

	/* The Read access / Write access cell of a role. */
	accessCell: function(name, list) {
		if (!this.accessAvailable)
			return E('em', _('(unavailable)'));
		var a = this.accessOf(name);
		if (!a)
			return list == 'read'
				? E('em', { 'class': 'luci-sso-no-entry' }, _('Not set: edit this role and Save & Apply, or its users cannot log in'))
				: NONE;
		var read = withoutBaseline(a.read);
		if (list == 'read' && !read.length && !a.write.length)
			return E('em', { 'class': 'luci-sso-no-access' }, _('None: this role grants no access'));
		var items = (list == 'read') ? read : L.toArray(a.write);
		if (items.length == 1 && items[0] === '*')
			return E('span', { 'title': '*' }, (list == 'read') ? _('Everything') : _('Full admin'));
		return renderList(items);
	},

	/* Whether the page holds permission edits that rpcd does not have yet. */
	hasAccessEdits: function() {
		if (!this.accessAvailable)
			return false;
		var roles = uci.sections('luci-sso', 'role').map(function(s) { return s['.name']; });
		return Object.keys(this.deleted).some(function(n) { return roles.indexOf(n) < 0; }) ||
			Object.keys(this.edited).some(function(n) { return roles.indexOf(n) >= 0; });
	},

	/* Writes the edited and deleted roles' permissions, then waits for rpcd
	 * to reload with them. Resolves true once they are in force, false when
	 * the reload did not finish in time; rejects when rpcd refuses one. */
	writeAccess: function() {
		var roles = uci.sections('luci-sso', 'role').map(function(s) { return s['.name']; });
		var tasks = [];

		Object.keys(this.deleted).forEach(function(name) {
			if (roles.indexOf(name) >= 0) return;
			tasks.push(callDeleteRole(name).then(function(reply) {
				if (reply && reply.error == 'NOT_FOUND') return;
				checkReply(name, reply);
			}));
		});
		Object.keys(this.edited).forEach(L.bind(function(name) {
			if (roles.indexOf(name) < 0) return;
			var a = this.edited[name];
			tasks.push(callSetRole(name, withoutBaseline(a.read), a.write).then(function(reply) {
				checkReply(name, reply);
			}));
		}, this));

		if (!tasks.length)
			return Promise.resolve(true);
		return Promise.all(tasks).then(awaitReload);
	},

	/* The permission half of Save & Apply, shown in LuCI's apply dialog. On
	 * success the page reloads, as after any apply; on failure the edits stay
	 * on the page, to fix and apply again. */
	applyAccess: function() {
		var reload = function() { window.location = window.location.href.split('#')[0]; };

		ui.changes.displayStatus('notice spinning',
			E('p', _('Saving role permissions; rpcd is reloading to apply them…')));

		return this.writeAccess().then(L.bind(function(done) {
			if (!done)
				throw new Error(_('rpcd did not finish reloading; the new permissions may not be in force yet.'));
			this.edited = {};
			this.deleted = {};
			ui.changes.displayStatus('notice', E('p', _('Role permissions saved and in force.')));
			return sleep(1500).then(reload);
		}, this)).catch(L.bind(function(e) {
			ui.changes.displayStatus('warning', [
				E('h4', _('Role permissions not saved')),
				E('p', [ e.message ]),
				E('div', { 'class': 'right' }, E('button', {
					'class': 'btn cbi-button',
					'click': L.bind(function() {
						ui.changes.displayStatus(false);
						return callListRoles().then(L.bind(function(data) {
							var edited = this.edited, deleted = this.deleted;
							this.loadAccess(data);
							this.edited = edited;
							this.deleted = deleted;
							return this._map.load().then(L.bind(this._map.reset, this._map));
						}, this)).catch(function(err) {
							/* The edits are still on the page; Save & Apply tries again. */
							ui.addNotification(null, E('p', [ _('Could not reload the role permissions from rpcd: %s').format(err.message) ]), 'warning');
						});
					}, this)
				}, _('Dismiss')))
			]);
		}, this));
	},

	/* Save & Apply: stage and apply the UCI changes as LuCI does, and write
	 * the permissions only once the apply has gone through (see the comment
	 * at the top). */
	handleSaveApply: function(ev, mode) {
		var page = this;
		var checked = (mode == '0');

		return this.handleSave(ev).then(function() {
			if (!page.hasAccessEdits())
				return ui.changes.apply(checked);

			return uci.changes().then(function(changes) {
				var pending = Object.keys(changes || {}).some(function(c) { return L.toArray(changes[c]).length > 0; });
				if (!pending)
					return page.applyAccess();

				if (!page.applyArmed) {
					page.applyArmed = true;
					document.addEventListener('uci-applied', function() {
						page.applyArmed = false;
						/* Right after this event, LuCI arms a timer that
						 * reloads the page in L.env.apply_display seconds.
						 * Only applyAccess may reload it: once the permissions
						 * are in force, and never when they fail, or the
						 * reload would throw away the edits it keeps. So the
						 * value is HOLD_RELOAD_S while LuCI arms that timer,
						 * and back to LuCI's own as soon as it has, for its
						 * other timers (closing a notice, the reload after a
						 * revert). */
						var display = L.env.apply_display;
						L.env.apply_display = HOLD_RELOAD_S;
						window.setTimeout(function() { L.env.apply_display = display; }, 0);
						Promise.resolve().then(L.bind(page.applyAccess, page));
					}, { once: true });
				}
				ui.changes.apply(checked);
			});
		});
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

	handleReset: function() {
		this.edited = {};
		this.deleted = {};
		this.rebindTo = null;
		return this._map.reset();
	},

	/* The issuer the roles' subject rules belong to, or null when they have
	 * none yet: the one the button chose, else sub_issuer, else, for rules
	 * the page found without one, the Issuer URL it was loaded with. */
	subOwner: function() {
		if (this.rebindTo)
			return this.rebindTo;
		var bound = uci.get('luci-sso', 'default', 'sub_issuer');
		if (bound)
			return bound;
		return this.loadedSubs ? (this.loadedIssuer || null) : null;
	},

	/* Fills a subject-rule slot for the Issuer URL `issuer`: a warning, with
	 * the button, when the rules belong to another issuer; a notice when the
	 * button has moved them to this one, until saved; nothing otherwise. */
	renderSubIssuer: function(slot, issuer) {
		if (!slot)
			return;
		var owner = this.subOwner();
		var bound = uci.get('luci-sso', 'default', 'sub_issuer') || null;
		var subs = hasSubRules();
		slot.innerHTML = '';
		if (subs && owner && issuer && owner !== issuer) {
			slot.className = 'alert-message warning luci-sso-warning';
			slot.appendChild(E('p', {}, _('Subject rules belong to <code>%h</code> and are ignored for <code>%h</code>. A subject identifies one account only at its own provider.').format(owner, issuer)));
			slot.appendChild(E('button', {
				'class': 'cbi-button cbi-button-action luci-sso-rebind',
				'type': 'button',
				'click': L.bind(function(ev) {
					ev.preventDefault();
					this.rebindTo = issuer;
					this.updateSubIssuer(issuer);
				}, this)
			}, [ _('Use these subject rules with the new provider') ]));
			slot.removeAttribute('hidden');
		}
		else if (subs && this.rebindTo && this.rebindTo === issuer && bound !== issuer) {
			slot.className = 'alert-message notice luci-sso-warning';
			slot.appendChild(E('p', {}, _('Subject rules will be used with <code>%h</code> after Save &amp; Apply.').format(issuer)));
			slot.removeAttribute('hidden');
		}
		else {
			slot.className = 'luci-sso-warning';
			slot.setAttribute('hidden', '');
		}
	},

	/* Refreshes every subject-rule slot, for the Issuer URL in the form. */
	updateSubIssuer: function(issuer) {
		document.querySelectorAll('[data-warning="sub-issuer"]').forEach(L.bind(function(slot) {
			this.renderSubIssuer(slot, issuer);
		}, this));
	},

	/* Run on each save of the form, once its values are parsed into UCI:
	 * sets sub_issuer to the issuer the subject rules belong to (subOwner),
	 * or to the Issuer URL when they have none yet, and removes it when no
	 * role has a subject rule. So a first save binds the rules to the Issuer
	 * URL, and one after an Issuer URL change keeps them bound to the old
	 * issuer until the button moves them. */
	bindSubIssuer: function() {
		var bound = uci.get('luci-sso', 'default', 'sub_issuer') || '';
		var next = hasSubRules() ? (this.subOwner() || uci.get('luci-sso', 'default', 'issuer_url') || '') : '';
		this.rebindTo = null;
		if (next === bound)
			return;
		if (next)
			uci.set('luci-sso', 'default', 'sub_issuer', next);
		else
			uci.unset('luci-sso', 'default', 'sub_issuer');
	},

	render: function(data) {
		var m, s, o;
		var page = this;

		this.loadAccess(data[0]);
		this.aclGroups = Array.isArray(data[1]) ? data[1] : null;
		/* What the subject rules were found with (see subOwner). */
		this.rebindTo = null;
		this.loadedIssuer = uci.get('luci-sso', 'default', 'issuer_url') || '';
		this.loadedSubs = hasSubRules();
		if (!this.accessAvailable)
			ui.addNotification(null, E('p', _('The role permissions could not be loaded from rpcd (luci-sso object): they are shown as unavailable and cannot be changed. Is the luci-sso package fully installed?')), 'warning');

		m = this._map = new form.Map('luci-sso',
			_('Single Sign-On'),
			_('Log in to LuCI with your identity provider, using OpenID Connect (OIDC).'));
		/* Each save binds the subject rules to their issuer, once the form's
		 * values are in UCI and before LuCI stages them. */
		var parse = m.parse;
		m.parse = function() {
			return parse.apply(this, arguments).then(function() { page.bindSubIssuer(); });
		};

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
		s.handleRemove = function(section_id, ev) {
			delete page.edited[section_id];
			page.deleted[section_id] = true;
			return form.GridSection.prototype.handleRemove.call(this, section_id, ev);
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
		column('_subs', _('Subjects'), 'sub');

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

		/* Read and write access live in rpcd, not in /etc/config/luci-sso:
		 * these options load from and write to the page's copy, which
		 * Save & Apply sends to the luci-sso object. The router's access
		 * groups are offered as suggestions; any name or pattern can be
		 * typed. */
		var accessOption = function(list, title, description, everything) {
			o = s.option(form.DynamicList, list, title, description);
			o.modalonly = true;
			o.rmempty = true;
			o.readonly = !page.accessAvailable || null;
			o.placeholder = _('-- choose or type a group --');
			if (page.aclGroups) {
				o.value('*', everything);
				page.aclGroups.forEach(function(g) {
					if (g !== BASELINE) o.value(g);
				});
			}
			o.load = function(section_id) {
				var a = page.accessOf(section_id);
				return a ? (list == 'read' ? withoutBaseline(a.read) : a.write) : [];
			};
			o.write = function(section_id, value) {
				if (page.accessAvailable) page.editAccess(section_id, list, value);
			};
			o.remove = function(section_id) {
				if (page.accessAvailable) page.editAccess(section_id, list, []);
			};
			return o;
		};

		/* The dialog's own Save only keeps the edit on the page. */
		o = s.option(form.DummyValue, '_access_note');
		o.modalonly = true;
		o.rawhtml = true;
		o.cfgvalue = function() {
			return '<em class="luci-sso-access-note">' +
				_('Changes here are kept on the page until you Save &amp; Apply it.') + '</em>';
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
