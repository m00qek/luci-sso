'use strict';

(function() {
	console.log("LuCI SSO: Hook loaded");

	// Use a unique ID to prevent double injection
	var BTN_ID = 'luci-sso-login-btn';
	var SEP_ID = 'luci-sso-separator';

	function injectSsoButton() {
		// 1. Check if we already have a visible button
		if (document.getElementById(BTN_ID)) {
			return true;
		}

		// 2. Find the Primary Action Button
		// We look for the "Log in" button produced by LuCI.js (not the hidden static one)
		var primaryBtn = null;
        
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
			// Ignore the hidden static form
			if (c.offsetParent !== null || c.closest('.modal')) {
				// Heuristic: Must be a submit-like button. <input> carries its
				// label in value=, not as a text node, so textContent is empty
				// for the generic template's submit input.
				var label = (c.tagName === 'INPUT') ? (c.value || '') : (c.textContent || '');
				if (label.match(/Log in|Anmelden|Login|Sign in/i) || c.classList.contains('cbi-button-apply')) {
					primaryBtn = c;
					break;
				}
			}
		}

		if (!primaryBtn) return false;

		// 3. Create UI
		var container = primaryBtn.parentNode;
		// Bail out if the button has no element parent to attach to.
		if (!container || container.nodeType !== Node.ELEMENT_NODE) {
			return false;
		}
        
		var separator = document.createElement('div');
		separator.id = SEP_ID;
		separator.style.textAlign = 'center';
		separator.style.margin = '2px 0';
		// Dim the inherited text colour rather than fixing one, so the
		// separator stays readable on light and dark themes alike.
		separator.style.opacity = '0.7';
		separator.style.fontSize = '0.9em';
		separator.textContent = '— or —';

		var ssoBtn = document.createElement('button');
		ssoBtn.id = BTN_ID;
		ssoBtn.type = 'button';
		// Copy the primary button's classes and set no colours of our own, so
		// the button takes the active theme's look, dark themes included.
		ssoBtn.className = primaryBtn.className;
		ssoBtn.style.width = '100%';
		ssoBtn.style.marginTop = '5px';
		ssoBtn.textContent = 'Login with SSO';

		ssoBtn.onclick = function(e) {
			e.preventDefault();
			ssoBtn.disabled = true;
			ssoBtn.textContent = 'Redirecting...';
            
			// Always start the SSO flow over HTTPS, even from an HTTP page: every
			// cookie it sets is Secure.
			window.location.href = 'https://' + window.location.host + '/cgi-bin/luci-sso';
		};

		// 4. Inject
		// Usually buttons are in a .cbi-page-actions or similar div
		container.appendChild(separator);
		container.appendChild(ssoBtn);
        
		return true;
	}

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