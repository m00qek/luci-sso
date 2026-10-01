'use strict';

(function() {
	console.log("LuCI SSO: Hook loaded");

	// Use a unique ID to prevent double injection
	var BTN_ID = 'luci-sso-login-btn';
	var SEP_ID = 'luci-sso-separator';
	var MSG_ID = 'luci-sso-message';

	var BTN_LABEL = 'Login with SSO';
	var BTN_BUSY_LABEL = 'Redirecting...';

	// How long the button waits for the browser to leave the page. The router
	// answers the click at once with a redirect to the IdP, so a page still
	// here after this long means the browser cannot reach the IdP.
	var IDP_TIMEOUT_MS = 15000;
	var IDP_TIMEOUT_TEXT = 'The identity provider is not responding. ' +
		'Check that this device can reach it, then try again.';

	var redirectTimer = null;

	function findPrimaryButton() {
		// We look for the "Log in" button produced by LuCI.js (not the hidden static one)
		// Target: The positive button in the login form or modal.
		// Two different markups exist upstream, and only the first was handled
		// before (issue #10):
		//   bootstrap (own sysauth.ut):
		//     <button class="btn cbi-button-positive important">Log in</button>
		//   luci-base generic sysauth.ut, used by material, openwrt,
		//   openwrt-2020 and footstrap:
		//     <input type="submit" value="Log in" class="btn cbi-button cbi-button-apply" />
		// This script is only ever injected into sysauth.ut, so matching
		// .cbi-button-apply cannot collide with a Save & Apply button — the
		// login page has none.
		var candidates = document.querySelectorAll('.cbi-button-positive, .btn.login, button.important, .cbi-button-apply');
		for (var i = 0; i < candidates.length; i++) {
			var c = candidates[i];
			// Our own button is a button.important labelled "Login with SSO":
			// never take it for the primary one.
			if (c.id === BTN_ID) continue;
			// Ignore the hidden static form
			if (c.offsetParent !== null || c.closest('.modal')) {
				// Heuristic: Must be a submit-like button. <input> carries its
				// label in value=, not as a text node, so textContent is empty
				// for the generic template's submit input.
				var label = (c.tagName === 'INPUT') ? (c.value || '') : (c.textContent || '');
				if (label.match(/Log in|Anmelden|Login|Sign in/i) || c.classList.contains('cbi-button-apply')) {
					return c;
				}
			}
		}
		return null;
	}

	function createSeparator() {
		var separator = document.createElement('div');
		separator.id = SEP_ID;
		separator.style.textAlign = 'center';
		separator.style.margin = '2px 0';
		// Dim the inherited text colour rather than fixing one, so the
		// separator stays readable on light and dark themes alike.
		separator.style.opacity = '0.7';
		separator.style.fontSize = '0.9em';
		separator.textContent = '— or —';
		return separator;
	}

	function createSsoButton() {
		var ssoBtn = document.createElement('button');
		ssoBtn.id = BTN_ID;
		ssoBtn.type = 'button';
		// The theme's own blue action button, filled like the primary one
		// (important). Set no colours of our own, so the button takes the
		// active theme's look, dark themes included.
		ssoBtn.className = 'btn cbi-button cbi-button-action important';
		ssoBtn.style.width = '100%';
		ssoBtn.style.marginTop = '5px';
		ssoBtn.textContent = BTN_LABEL;

		ssoBtn.onclick = function(e) {
			e.preventDefault();
			hideMessage();
			clearTimeout(redirectTimer);
			ssoBtn.disabled = true;
			ssoBtn.textContent = BTN_BUSY_LABEL;

			// Still on this page after the timeout: the browser is stuck on
			// its way to the IdP. Give the button back and say why.
			redirectTimer = setTimeout(function() {
				resetButton();
				showMessage(IDP_TIMEOUT_TEXT);
			}, IDP_TIMEOUT_MS);

			// Always start the SSO flow over HTTPS, even from an HTTP page: every
			// cookie it sets is Secure.
			// LuCI shows its login page at the address that was asked for, so
			// pass that page on as return_to: the router opens it after the
			// login, as the password login does (issue #27). The router checks
			// it and keeps it on the router. The #fragment is not sent.
			var page = window.location.pathname + window.location.search;
			window.location.href = 'https://' + window.location.host + '/cgi-bin/luci-sso' +
				'?return_to=' + encodeURIComponent(page);
		};

		return ssoBtn;
	}

	// Gives the button back its label and makes it clickable again.
	function resetButton() {
		clearTimeout(redirectTimer);
		redirectTimer = null;
		var ssoBtn = document.getElementById(BTN_ID);
		if (ssoBtn) {
			ssoBtn.disabled = false;
			ssoBtn.textContent = BTN_LABEL;
		}
	}

	// Shows a message under the button, styled by the theme's own alert
	// classes. The text is set with textContent, never parsed as HTML.
	function showMessage(text) {
		var ssoBtn = document.getElementById(BTN_ID);
		if (!ssoBtn) return;
		var msg = document.getElementById(MSG_ID);
		if (!msg) {
			msg = document.createElement('div');
			msg.id = MSG_ID;
			msg.className = 'alert-message warning';
			msg.setAttribute('role', 'alert');
			msg.style.marginTop = '5px';
		}
		msg.textContent = text;
		ssoBtn.insertAdjacentElement('afterend', msg);
	}

	function hideMessage() {
		var msg = document.getElementById(MSG_ID);
		if (msg) msg.parentNode.removeChild(msg);
	}

	// Puts each node right after the previous one, starting after anchor. A
	// node already in place is not touched, so a check that finds the order
	// right causes no DOM mutation (and does not wake the observer again).
	function placeAfter(anchor, nodes) {
		var prev = anchor;
		for (var i = 0; i < nodes.length; i++) {
			var node = nodes[i];
			if (!node) continue;
			if (prev.nextElementSibling !== node) {
				prev.insertAdjacentElement('afterend', node);
			}
			prev = node;
		}
	}

	// Makes sure the page shows [Log in], "— or —", [Login with SSO], in that
	// order, right after the primary button. LuCI can move the login form's
	// nodes after the injection (the bootstrap view moves them into a modal),
	// so every check puts them back in place rather than only adding them once.
	function injectSsoButton() {
		var ssoBtn = document.getElementById(BTN_ID);
		var primaryBtn = findPrimaryButton();

		if (!primaryBtn) return !!ssoBtn;

		// Bail out if the button has no element parent to attach to.
		var container = primaryBtn.parentNode;
		if (!container || container.nodeType !== Node.ELEMENT_NODE) {
			return !!ssoBtn;
		}

		var separator = document.getElementById(SEP_ID) || createSeparator();
		if (!ssoBtn) ssoBtn = createSsoButton();

		placeAfter(primaryBtn, [separator, ssoBtn, document.getElementById(MSG_ID)]);

		return true;
	}

	// The timer must stop once the browser really leaves the page, so a slow
	// but successful redirect never shows the message. pagehide fires when the
	// new page replaces this one. beforeunload would be too early: it fires as
	// soon as the click starts the navigation, before the IdP has answered.
	window.addEventListener('pagehide', function() {
		clearTimeout(redirectTimer);
		redirectTimer = null;
	});

	// Back from the IdP with the Back button, the page may come from the
	// back/forward cache as it was left: reset the button and drop any message.
	window.addEventListener('pageshow', function(e) {
		if (e.persisted) {
			resetButton();
			hideMessage();
		}
	});

	function init() {
		// Initial check
		injectSsoButton();

		// Heavy-duty observer to handle LuCI.js dynamic rendering
		// Debounce: LuCI re-renders often, so coalesce bursts of mutations.
		var debounceTimer;
		var observer = new MutationObserver(function() {
			clearTimeout(debounceTimer);
			debounceTimer = setTimeout(injectSsoButton, 100);
		});

		observer.observe(document.body, {
			childList: true,
			subtree: true,
			attributes: false
		});

		// Polling as ultimate fallback
		var attempts = 0;
		var interval = setInterval(function() {
			if (injectSsoButton() || ++attempts > 30) {
				clearInterval(interval);
			}
		}, 500);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', function() {
			fetch('/cgi-bin/luci-sso?action=enabled')
				.then(function(r) { return r.json(); })
				.then(function(data) {
					if (data && data.enabled) init();
				})
				.catch(function(e) { console.error("LuCI SSO: Failed to check enabled status", e); });
		});
	} else {
		fetch('/cgi-bin/luci-sso?action=enabled')
			.then(function(r) { return r.json(); })
			.then(function(data) {
				if (data && data.enabled) init();
			})
			.catch(function(e) { console.error("LuCI SSO: Failed to check enabled status", e); });
	}
})();
