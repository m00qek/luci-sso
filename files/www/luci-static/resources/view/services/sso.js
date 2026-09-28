'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require rpc';
'require request';

/*
 * A role has two halves:
 *  - its matching rules (email, group) and its place in the order: a
 *    `role` section of /etc/config/luci-sso, edited through UCI like any
 *    other LuCI form, and applied with Save & Apply;
 *  - its permissions (read, write): the rpcd login entry luci_sso_<role>,
 *    which only the `luci-sso` ubus object may write. The page loads them
 *    with list_roles and, when the form is saved, writes the roles edited
 *    since with set_role and removes the deleted ones with delete_role.
 *    Each write makes rpcd reload; the page waits for it before it reports
 *    the save done.
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

/* Every role's read list grants this group (the ubus object adds it), so the
 * page neither shows it nor lets it be removed. */
var BASELINE = 'unauthenticated';

/* How long to wait for rpcd to reload after a write. */
var RELOAD_TIMEOUT_MS = 30000;
var RELOAD_POLL_MS = 500;

function renderList(items) {
	if (!items || !items.length) return _('(none)');
	return items.join(', ');
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

/* A reply of the luci-sso object: its own errors come back as a result. */
function checkReply(name, reply) {
	if (reply && reply.error)
		throw new Error(_('Role "%s": %s').format(name, reply.message || reply.error));
	return reply;
}

return view.extend({
	load: function() {
		return callListRoles().catch(function(e) {
			return { failed: e };
		});
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

	/* The Read Access / Write Access cell of a role. */
	accessCell: function(name, list) {
		if (!this.accessAvailable)
			return E('em', _('(unavailable)'));
		var a = this.accessOf(name);
		if (!a)
			return list == 'read'
				? E('em', { 'class': 'luci-sso-no-entry' }, _('Not set: edit and save this role, or its users cannot log in'))
				: E('em', _('(none)'));
		var read = withoutBaseline(a.read);
		if (list == 'read' && !read.length && !a.write.length)
			return E('em', { 'class': 'luci-sso-no-access' }, _('(none): this role grants no access'));
		return renderList(list == 'read' ? read : a.write);
	},

	/* Writes the edited and deleted roles' permissions, then waits for rpcd
	 * to reload with them. */
	saveAccess: function() {
		if (!this.accessAvailable)
			return Promise.resolve();

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
			return Promise.resolve();

		var note = ui.addNotification(null,
			E('p', { 'class': 'spinning' }, _('Saving role permissions; rpcd is reloading to apply them…')), 'info');

		return Promise.all(tasks).then(awaitReload).then(L.bind(function(done) {
			return callListRoles().then(L.bind(function(data) {
				this.loadAccess(data);
				note.remove();
				if (!done)
					throw new Error(_('rpcd did not finish reloading; the new permissions may not be in force yet.'));
				ui.addTimeLimitedNotification(null, E('p', _('Role permissions saved and in force.')), 5000, 'info');
				return this._map.reset();
			}, this));
		}, this)).catch(function(e) {
			note.remove();
			ui.addNotification(null, E('p', e.message), 'danger');
			throw e;
		});
	},

	handleSave: function(ev) {
		return this.super('handleSave', [ ev ]).then(L.bind(this.saveAccess, this));
	},

	handleReset: function() {
		this.edited = {};
		this.deleted = {};
		return this._map.reset();
	},

	render: function(data) {
		var m, s, o;
		var page = this;

		this.loadAccess(data);
		if (!this.accessAvailable)
			ui.addNotification(null, E('p', _('The role permissions could not be loaded from rpcd (luci-sso object): they are shown as unavailable and cannot be changed. Is the luci-sso package fully installed?')), 'warning');

		m = this._map = new form.Map('luci-sso',
			_('SSO Login'),
			_('Configure OpenID Connect (OIDC) Single Sign-On for LuCI.'));

		/* ------------------------------------------------------------------ */
		/* OIDC Provider                                                        */
		/* ------------------------------------------------------------------ */
		s = m.section(form.NamedSection, 'default', 'oidc', _('Settings'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable SSO'));
		o.rmempty = false;

		o = s.option(form.Value, 'issuer_url', _('Issuer URL'),
		        _('OIDC discovery base URL. Must use HTTPS and exactly match the issuer your provider declares.'));
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (value && !value.match(/^https:\/\//))
				return _('Must use HTTPS');
			return true;
		};
		o.placeholder = 'https://accounts.google.com';

		o = s.option(form.Value, 'client_id', _('Client ID'));
		o.rmempty = false;

		o = s.option(form.Value, 'client_secret', _('Client Secret'));
		o.password = true;
		o.rmempty = false;

		o = s.option(form.Value, 'redirect_uri', _('Redirect URI'),
		        _('Callback URL registered with the identity provider. Must use HTTPS.'));
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

		o = s.option(form.Value, 'scope', _('Scopes'),
		        _('Space-separated OIDC scopes. Add <code>groups</code> if your provider supports group claims.'));
		o.placeholder = 'openid profile email';
		o.rmempty = true;

		o = s.option(form.Flag, 'require_email_verified', _('Require Verified Email'),
		        _('Match a user by email address only if the provider marks it as verified (<code>email_verified</code>). ' +
		          'Group matching is not affected. ' +
		          'See <a href="https://m00qek.github.io/luci-sso/explanation/roles-and-permissions/#verified-email-addresses" target="_blank">verified email addresses</a>.'));
		/* On when the option is unset, as the backend treats it. */
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'clock_tolerance', _('Clock Tolerance'),
		        _('Allowed clock skew in seconds applied to JWT validation (0–3600).'));
		o.datatype = 'range(0,3600)';
		o.default = '60';
		o.placeholder = '60';
		o.rmempty = false;

		o = s.option(form.Value, 'internal_issuer_url', _('Internal Issuer URL'),
		        _('Physical URL the router uses for back-channel requests (token exchange, JWKS fetch). ' +
		          'Leave empty if the router can reach the Issuer URL directly. ' +
		          'See <a href="https://m00qek.github.io/luci-sso/how-to/sysadmin/split-horizon/" target="_blank">split-horizon networking</a>.'));
		o.optional = true;
		o.rmempty = true;
		o.validate = function(section_id, value) {
			if (value && !value.match(/^https:\/\//))
				return _('Must use HTTPS');
			return true;
		};
		o.placeholder = 'https://' + window.location.hostname + ':8443';

		/* ------------------------------------------------------------------ */
		/* Users                                                                */
		/* ------------------------------------------------------------------ */
		s = m.section(form.GridSection, 'role', _('Users'),
			_('A user gets the <strong>first</strong> role, from the top, whose emails or groups match. ' +
			  'Drag the rows to change the order; roles are not merged.') + '<br />' +
			_('Read and write access are the role\'s rpcd login entry. They are written when you press Save or Save &amp; Apply, ' +
			  'and are in force once rpcd has reloaded; emails, groups and order take effect with Save &amp; Apply.'));
		s.addremove = true;
		s.anonymous = false;
		s.sortable = true;
		s.modaledit = true;
		s.nodescriptions = true;
		s.modaltitle = function(section_id) {
			return _('User Role: %s').format(section_id);
		};
		s.handleAdd = function(ev, name) {
			if (name && name.trim() === 'default') {
				ui.addNotification(null,
					E('p', {}, _('The name "default" is reserved for OIDC provider settings. Choose a different role name.')),
					'danger');
				return;
			}
			return form.GridSection.prototype.handleAdd.call(this, ev, name);
		};
		s.handleRemove = function(section_id, ev) {
			delete page.edited[section_id];
			page.deleted[section_id] = true;
			return form.GridSection.prototype.handleRemove.call(this, section_id, ev);
		};

		/* --- Table columns (visible inline) --- */
		o = s.option(form.DummyValue, '_emails', _('Emails'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return renderList(L.toArray(uci.get('luci-sso', section_id, 'email')));
		};

		o = s.option(form.DummyValue, '_groups', _('Groups'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return renderList(L.toArray(uci.get('luci-sso', section_id, 'group')));
		};

		o = s.option(form.DummyValue, '_read', _('Read Access'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return page.accessCell(section_id, 'read');
		};

		o = s.option(form.DummyValue, '_write', _('Write Access'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return page.accessCell(section_id, 'write');
		};

		/* --- Modal fields (edit popup only) --- */
		o = s.option(form.DynamicList, 'email', _('Email Addresses'),
			_('Match by OIDC <code>email</code> claim (case-insensitive).'));
		o.modalonly = true;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'group', _('Groups'),
			_('Match by OIDC <code>groups</code> claim (case-sensitive).'));
		o.modalonly = true;
		o.rmempty = true;

		/* Read and write access live in rpcd, not in /etc/config/luci-sso:
		 * these options load from and write to the page's copy, which
		 * saveAccess() sends to the luci-sso object. */
		var accessOption = function(list, title, description) {
			o = s.option(form.DynamicList, list, title, description);
			o.modalonly = true;
			o.rmempty = true;
			o.readonly = !page.accessAvailable || null;
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
				_('Permission changes take effect when you click Save at the bottom of the page.') + '</em>';
		};

		accessOption('read', _('Read Access'),
			_('LuCI access groups granted read access. <code>*</code> reads every group. ' +
			  '<code>unauthenticated</code> is always included, since LuCI needs it on every page, and is not listed here. ' +
			  'With no other group, the role\'s users can log in but see nothing.'));

		accessOption('write', _('Write Access'),
			_('LuCI access groups granted write access, which includes read access. <code>*</code> makes the role a full admin.'));

		return m.render();
	}
});
