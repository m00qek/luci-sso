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
        
        // Target: The positive button in the login form or modal
        var candidates = document.querySelectorAll('.cbi-button-positive, .btn.login, button.important');
        for (var i = 0; i < candidates.length; i++) {
            var c = candidates[i];
            // Ignore the hidden static form
            if (c.offsetParent !== null || c.closest('.modal')) {
                // Heuristic: Must be a submit-like button
                if (c.textContent.match(/Log in|Anmelden|Login|Sign in/i) || c.classList.contains('cbi-button-apply')) {
                    primaryBtn = c;
                    break;
                }
            }
        }

        if (!primaryBtn) return false;

        // 3. Create UI
        var container = primaryBtn.parentNode;
        // Defensive Check (Blocker #1 in 1770661270)
        if (!container || container.nodeType !== Node.ELEMENT_NODE) {
            return false;
        }
        
        var separator = document.createElement('div');
        separator.id = SEP_ID;
        separator.style.textAlign = 'center';
        separator.style.margin = '2px 0';
        separator.style.color = '#666';
        separator.style.fontSize = '0.9em';
        separator.textContent = '— or —';

        var ssoBtn = document.createElement('button');
        ssoBtn.id = BTN_ID;
        ssoBtn.type = 'button';
        ssoBtn.className = primaryBtn.className; 
        ssoBtn.style.width = '100%';
        ssoBtn.style.marginTop = '5px'; 
        
        // High-Contrast Blue Professional Style
        ssoBtn.style.setProperty('background', 'linear-gradient(#337ab7, #2e6da4)', 'important');
        ssoBtn.style.setProperty('border-color', '#2e6da4', 'important');
        ssoBtn.style.setProperty('color', '#ffffff', 'important');
        ssoBtn.style.setProperty('text-shadow', 'none', 'important');
        ssoBtn.textContent = 'Login with SSO';

        ssoBtn.onclick = function(e) {
            e.preventDefault();
            ssoBtn.disabled = true;
            ssoBtn.textContent = 'Redirecting...';
            
            // Absolute redirect to preserve scheme/host
            window.location.href = window.location.protocol + '//' + window.location.host + '/cgi-bin/luci-sso';
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
        // Nitpick in 1770661270: Debounce to reduce CPU load
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
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();