// Mobile menu toggle
function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    const btn = document.getElementById('mobile-menu-btn');
    if (menu) {
        menu.classList.toggle('mobile-open');
        if (btn) {
            btn.textContent = menu.classList.contains('mobile-open') ? '✕' : '☰';
        }
    }
}

// Close mobile menu when clicking outside
document.addEventListener('click', function (e) {
    const menu = document.getElementById('mobile-menu');
    const btn = document.getElementById('mobile-menu-btn');
    if (menu && btn && !menu.contains(e.target) && !btn.contains(e.target)) {
        menu.classList.remove('mobile-open');
        if (btn) btn.textContent = '☰';
    }
});

// Close mobile menu on window resize (if becomes desktop)
window.addEventListener('resize', function () {
    if (window.innerWidth > 900) {
        const menu = document.getElementById('mobile-menu');
        const btn = document.getElementById('mobile-menu-btn');
        if (menu) menu.classList.remove('mobile-open');
        if (btn) btn.textContent = '☰';
    }
});

// Header settings dropdown (dark/light toggle)
(function () {
    const settingsBtn = document.getElementById('settings-btn');
    const settingsDropdown = document.getElementById('settings-dropdown');
    const darkToggle = document.getElementById('dark-mode-toggle');

    function closeDropdown() {
        if (settingsDropdown) {
            settingsDropdown.hidden = true;
            if (settingsBtn) settingsBtn.setAttribute('aria-expanded', 'false');
        }
    }

    if (settingsBtn && settingsDropdown) {
        settingsBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            settingsDropdown.hidden = !settingsDropdown.hidden;
            settingsBtn.setAttribute('aria-expanded', String(!settingsDropdown.hidden));
            if (!settingsDropdown.hidden) {
                const input = settingsDropdown.querySelector('input, a, button');
                if (input) input.focus();
            }
        });

        document.addEventListener('click', function (e) {
            if (!settingsDropdown.contains(e.target) && !settingsBtn.contains(e.target)) {
                closeDropdown();
            }
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') closeDropdown();
        });
    }

    // Theme handling: body gets class 'theme-light' for light mode.
    function applyTheme(theme) {
        // Toggle on both <html> and <body> so CSS variable overrides reliably apply
        const root = document.documentElement;
        if (theme === 'light') {
            root.classList.add('theme-light');
            document.body.classList.add('theme-light');
            if (darkToggle) darkToggle.checked = false;
        } else {
            root.classList.remove('theme-light');
            document.body.classList.remove('theme-light');
            if (darkToggle) darkToggle.checked = true;
        }
        try { localStorage.setItem('theme', theme); } catch (e) { /* ignore */ }
    }


    // Initialize theme from localStorage (apply saved theme on all pages, including home)
    try {
        const saved = localStorage.getItem('theme');
        if (saved === 'dark' || saved === 'light') {
            applyTheme(saved);
        } else {
            // If no saved preference, default to light
            applyTheme('light');
        }
    } catch (e) {
        applyTheme('light');
    }


    if (darkToggle) {
        darkToggle.addEventListener('change', function () {
            applyTheme(this.checked ? 'dark' : 'light');
        });
    }

    // reset-theme button removed; no extra UI here per request
})();

// Toggle wishlist globally and sync all heart icons across the page
async function toggleWishlist(productId, csrfToken) {
    // Determine CSRF token
    let token = csrfToken || null;
    if (!token) {
        // Try meta tag
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) token = meta.getAttribute('content');
    }

    // Find representative button(s) for this product
    const selector = `[data-product-id="${productId}"]`;
    const buttons = Array.from(document.querySelectorAll(`.wishlist-btn${selector}, .wishlist-btn-large${selector}, button${selector}.wishlist-btn, button${selector}.wishlist-btn-large`));

    // Also try to find forms with class wishlist-form whose action contains productId
    const forms = Array.from(document.querySelectorAll('form.wishlist-form'));
    forms.forEach(f => {
        try {
            const match = (f.getAttribute('action') || '').match(/\/wishlist\/(?:add|remove)\/(\d+)/);
            if (match && String(match[1]) === String(productId)) {
                // If there's a button inside, add to buttons list
                const b = f.querySelector('button');
                if (b && !buttons.includes(b)) buttons.push(b);
            }
        } catch (e) { /* ignore */ }
    });

    // If no button found, try to find any element with data-product-id
    if (!buttons.length) {
        const any = document.querySelectorAll(`[data-product-id="${productId}"]`);
        any.forEach(el => { if (!buttons.includes(el)) buttons.push(el); });
    }

    // Pick primary button for disabling/enabling UI while request runs
    const primary = buttons[0] || null;
    if (primary) {
        primary.disabled = true;
        primary.style.opacity = '0.6';
    }

    try {
        const formData = new FormData();
        if (token) formData.append('_csrf', token);

        const response = await fetch(`/api/wishlist/toggle/${productId}`, {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        });

        // If server returned a redirect (not JSON), treat as not authenticated
        const contentType = response.headers.get('content-type') || '';
        if (!response.ok) {
            // If redirected to login, try to send user there
            if (response.status === 401 || response.redirected) {
                window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname + window.location.search);
                return;
            }
        }

        let data = null;
        if (contentType.includes('application/json')) {
            data = await response.json();
        } else {
            // Non-JSON response (maybe login page) -> redirect
            window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname + window.location.search);
            return;
        }

        if (data && data.success) {
            const added = data.action === 'added';
            // Update all buttons for this product
            buttons.forEach(btn => {
                if (added) {
                    btn.classList.add('active');
                    btn.setAttribute('aria-pressed', 'true');
                } else {
                    btn.classList.remove('active');
                    btn.setAttribute('aria-pressed', 'false');
                }
            });

            // If showToast exists on page, use it; otherwise fallback to a small visual state change
            if (typeof showToast === 'function') {
                showToast(data.message, added ? 'success' : 'info');
            } else {
                // quick UI feedback using title attribute
                if (primary) primary.title = data.message;
            }
        } else {
            if (data && data.message) {
                if (typeof showToast === 'function') showToast(data.message, 'error');
                else alert(data.message);
            }
        }
    } catch (err) {
        console.error('Error toggling wishlist:', err);
        if (typeof showToast === 'function') showToast('Có lỗi xảy ra. Vui lòng thử lại.', 'error');
    } finally {
        if (primary) {
            primary.disabled = false;
            primary.style.opacity = '1';
        }
    }
}

// Attach delegated listeners: intercept wishlist-form submits and button clicks
document.addEventListener('click', function (e) {
    const btn = e.target.closest('.wishlist-btn, .wishlist-btn-large');
    if (!btn) return;
    // If it's a submit button inside a form, let submit handler handle it; but intercept buttons of type button
    const productId = btn.getAttribute('data-product-id') || btn.dataset.productId;
    if (!productId) return; // no productId -> nothing to do
    e.preventDefault();
    // read csrf if present on element
    const csrf = btn.dataset.csrf || null;
    toggleWishlist(productId, csrf);
});

document.addEventListener('submit', function (e) {
    const form = e.target.closest('form.wishlist-form');
    if (!form) return;
    // Try to extract productId from action
    const action = form.getAttribute('action') || '';
    const match = action.match(/\/wishlist\/(?:add|remove)\/(\d+)/);
    if (!match) return;
    e.preventDefault();
    const productId = match[1];
    const csrf = form.querySelector('input[name="_csrf"]')?.value || form.dataset.csrf || null;
    toggleWishlist(productId, csrf);
});

// Expose globally (some templates still call toggleWishlist inline)
window.toggleWishlist = toggleWishlist;
