'use strict';
'require view';
'require form';
'require uci';
'require ui';

function renderList(items) {
	if (!items || !items.length) return _('(none)');
	return items.join(', ');
}

return view.extend({
	handleReset: function() {
		return this._map.reset();
	},

	render: function() {
		var m, s, o;

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

		o = s.option(form.Value, 'scope', _('Scopes'),
		        _('Space-separated OIDC scopes. Add <code>groups</code> if your provider supports group claims.'));
		o.placeholder = 'openid profile email';
		o.rmempty = true;

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
			_('A user matches a role when any email or group condition is satisfied. ' +
			  'Permissions from all matched roles are merged.'));
		s.addremove = true;
		s.anonymous = false;
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
			return renderList(L.toArray(uci.get('luci-sso', section_id, 'read')));
		};

		o = s.option(form.DummyValue, '_write', _('Write Access'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			return renderList(L.toArray(uci.get('luci-sso', section_id, 'write')));
		};

		/* --- Modal fields (edit popup only) --- */
		o = s.option(form.DynamicList, 'email', _('Email Addresses'),
			_('Match by OIDC <code>email</code> claim (case-insensitive).'));
		o.modalonly = true;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'group', _('Groups'),
			_('Match by OIDC <code>groups</code> claim (case-sensitive). ' +
			  'For Pocket ID, include the <code>@PocketID</code> suffix.'));
		o.modalonly = true;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'read', _('Read Access'),
			_('LuCI access groups granted read access. Use <code>*</code> for all groups.'));
		o.modalonly = true;
		o.rmempty = true;

		o = s.option(form.DynamicList, 'write', _('Write Access'),
			_('LuCI access groups granted write access. Use <code>*</code> for all groups.'));
		o.modalonly = true;
		o.rmempty = true;

		return m.render();
	}
});
