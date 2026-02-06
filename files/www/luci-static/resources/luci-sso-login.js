'use strict';

(function() {
    console.log("LuCI SSO: Hook loaded");

    var injectionAttempts = 0;
    var maxAttempts = 20;

    function injectSsoButton() {
        // Find the visible login button
        var loginBtn = null;
        var buttons = document.querySelectorAll('button.cbi-button-positive, button.btn.login, .modal button');
        
        for (var i = 0; i < buttons.length; i++) {
            var b = buttons[i];
            // Check if it's a "Log in" button
            if (b.textContent.match(/Log in|Anmelden|Connexion|Entrar|Iniciar/i) || b.classList.contains('cbi-button-positive')) {
                // Ensure it's visible or inside a modal
                if (b.offsetWidth > 0 || b.offsetHeight > 0 || b.closest('.modal')) {
                    loginBtn = b;
                    break;
                }
            }
        }

        if (!loginBtn) {
            return false;
        }

        // Check if we already injected
        if (document.getElementById('luci-sso-login-btn')) {
            return true;
        }

        console.log("LuCI SSO: Found login button, injecting...");

        // Create a separator
        var separator = document.createElement('div');
        separator.id = 'luci-sso-separator';
        separator.style.textAlign = 'center';
        separator.style.margin = '10px 0';
        separator.style.color = '#666';
        separator.style.fontSize = '0.9em';
        separator.textContent = '— or —';

        // Create the SSO button
        var ssoBtn = document.createElement('button');
        ssoBtn.id = 'luci-sso-login-btn';
        
        // Use identical classes as the original button
        ssoBtn.className = loginBtn.className;
        
        ssoBtn.type = 'button';
        ssoBtn.style.width = '100%';
        ssoBtn.style.marginTop = '0px'; 
        
        // Apply blue gradient and border-color matching the success-color pattern
        // Success-medium: #4caf50 (Green) -> Blue equivalent: #337ab7
        // Success-low: #81c784 (Green) -> Blue equivalent: #5bc0de
        // Success-high: #388e3c (Green) -> Blue equivalent: #2e6da4
        
        ssoBtn.style.setProperty('background', 'linear-gradient(#337ab7, #5bc0de)', 'important');
        ssoBtn.style.setProperty('border-color', '#2e6da4', 'important');
        ssoBtn.style.setProperty('color', '#ffffff', 'important');
        
        ssoBtn.textContent = 'Login with SSO';

        ssoBtn.onclick = function() {
            ssoBtn.disabled = true;
            ssoBtn.textContent = 'Redirecting...';
            window.location.href = '/cgi-bin/luci-sso';
        };

        // Insert after the original login button
        loginBtn.parentNode.insertBefore(separator, loginBtn.nextSibling);
        separator.parentNode.insertBefore(ssoBtn, separator.nextSibling);
        
        return true;
    }

    function init() {
        if (!document.body) {
            setTimeout(init, 50);
            return;
        }

        console.log("LuCI SSO: Initializing observer");

        // Use MutationObserver to catch LuCI's dynamic modal rendering
        var observer = new MutationObserver(function(mutations) {
            injectSsoButton();
        });

        observer.observe(document.body, { childList: true, subtree: true });

        // Polling fallback
        var pollInterval = setInterval(function() {
            if (injectSsoButton() || ++injectionAttempts > maxAttempts) {
                clearInterval(pollInterval);
            }
        }, 500);

        // Immediate check
        injectSsoButton();
    }

    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        init();
    } else {
        document.addEventListener('DOMContentLoaded', init);
    }
})();