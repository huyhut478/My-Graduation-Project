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

/* Lightweight review image lightbox */
(function () {
    function createLightbox(imgSrc) {
        const overlay = document.createElement('div');
        overlay.style.position = 'fixed';
        overlay.style.left = 0;
        overlay.style.top = 0;
        overlay.style.right = 0;
        overlay.style.bottom = 0;
        overlay.style.background = 'rgba(0,0,0,0.85)';
        overlay.style.display = 'flex';
        overlay.style.alignItems = 'center';
        overlay.style.justifyContent = 'center';
        overlay.style.zIndex = 9999;
        overlay.style.padding = '24px';

        const img = document.createElement('img');
        img.src = imgSrc;
        img.style.maxWidth = '95%';
        img.style.maxHeight = '95%';
        img.style.borderRadius = '8px';
        img.style.boxShadow = '0 10px 40px rgba(0,0,0,0.8)';

        overlay.appendChild(img);
        overlay.addEventListener('click', () => document.body.removeChild(overlay));
        document.body.appendChild(overlay);
        // close on ESC
        function onEsc(e) { if (e.key === 'Escape') { document.body.removeChild(overlay); window.removeEventListener('keydown', onEsc); } }
        window.addEventListener('keydown', onEsc);
    }

    document.addEventListener('click', function (e) {
        const img = e.target.closest('.review img');
        if (!img) return;
        const src = img.getAttribute('src') || img.dataset.src;
        if (!src) return;
        createLightbox(src);
    });
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

// Header should scroll naturally with the page (no JS hiding).
// Keep --header-offset at 0 so sticky sidebars don't get overlapped.
(function () {
    // Header pin/unpin control: toggles header.fixed (pinned) state and persist in localStorage
    const header = document.querySelector('header');
    const btn = document.getElementById('header-pin-btn');

    function applyPinnedState(pinned) {
        if (!header) return;
        if (pinned) {
            header.classList.add('header-pinned');
            btn && btn.classList.add('active');
            if (btn) btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M6 15l6-6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
            // set offset to header height for sticky sidebars
            const h = Math.ceil(header.getBoundingClientRect().height);
            document.documentElement.style.setProperty('--header-offset', h + 'px');
            // add padding to body so page content doesn't get hidden under fixed header
            document.body.style.setProperty('padding-top', h + 'px');
            btn && btn.setAttribute('aria-pressed', 'true');
        } else {
            header.classList.remove('header-pinned');
            btn && btn.classList.remove('active');
            if (btn) btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
            document.documentElement.style.setProperty('--header-offset', '0px');
            document.body.style.removeProperty('padding-top');
            btn && btn.setAttribute('aria-pressed', 'false');
        }
    }

    // initialize from localStorage
    try {
        const saved = localStorage.getItem('headerPinned');
        const pinned = saved === 'true';
        applyPinnedState(pinned);
    } catch (e) { applyPinnedState(false); }

    // attach click handler
    if (btn) {
        btn.addEventListener('click', function () {
            try {
                const current = header.classList.contains('header-pinned');
                const next = !current;
                applyPinnedState(next);
                try { localStorage.setItem('headerPinned', next ? 'true' : 'false'); } catch (e) { }
            } catch (e) { console.error('header pin toggle failed', e); }
        });
    }

    // When pinned, recalc size on resize so padding-top and header-offset stay correct
    window.addEventListener('resize', function () {
        try {
            const pinnedNow = header && header.classList.contains('header-pinned');
            if (pinnedNow) applyPinnedState(true);
        } catch (e) { /* ignore */ }
    });

    // The floating pin button is fixed via CSS (bottom-right). Do not reposition it dynamically here
})();

// Expose globally (some templates still call toggleWishlist inline)
window.toggleWishlist = toggleWishlist;
/* ===== Reviews & product page interactions ===== */
(function () {
    // Helpers
    function qs(sel, ctx) { return (ctx || document).querySelector(sel); }
    function qsa(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }

    // Show review form
    const leaveCommentBtn = qs('#leave-comment-btn');
    const leaveReviewBtn = qs('#leave-review-btn');
    const reviewContainer = qs('#review-form-container');
    const questionsFormSection = qs('#questions-form-section');
    const reviewsFormSection = qs('#reviews-form-section');
    const cancelReviewBtn = qs('#cancel-review');
    const btnCancelQuestion = qs('.btn-cancel-question');

    // Comment/Question button - shows questions form
    if (leaveCommentBtn && reviewContainer) {
        leaveCommentBtn.addEventListener('click', function () {
            if (questionsFormSection) {
                questionsFormSection.style.display = 'block';
            }
            if (reviewsFormSection) {
                reviewsFormSection.style.display = 'none';
            }
            reviewContainer.style.display = 'block';
            reviewContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
        });
    }

    // Review button - shows review form
    if (leaveReviewBtn && reviewContainer) {
        leaveReviewBtn.addEventListener('click', function () {
            if (questionsFormSection) {
                questionsFormSection.style.display = 'none';
            }

            if (reviewsFormSection) {
                if (typeof window.userCanReview !== 'undefined' && !window.userCanReview) {
                    reviewsFormSection.style.display = 'none';
                } else {
                    reviewsFormSection.style.display = 'block';
                }
            }

            reviewContainer.style.display = 'block';
            reviewContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
        });
    }

    if (cancelReviewBtn && reviewContainer) {
        cancelReviewBtn.addEventListener('click', function () {
            reviewContainer.style.display = 'none';
            if (questionsFormSection) questionsFormSection.style.display = 'none';
            if (reviewsFormSection) reviewsFormSection.style.display = 'none';
        });
    }

    if (btnCancelQuestion && reviewContainer) {
        btnCancelQuestion.addEventListener('click', function () {
            if (questionsFormSection) questionsFormSection.style.display = 'none';
        });
    }

    // Star rating input
    const starInput = qs('#review-stars-input');
    const ratingInputEl = qs('#rating-input');
    if (starInput && ratingInputEl) {
        function setStars(val) {
            qsa('.star', starInput).forEach(s => {
                const v = Number(s.getAttribute('data-value')) || 0;
                s.textContent = v <= val ? '★' : '☆';
            });
            ratingInputEl.value = String(val);
        }
        starInput.addEventListener('click', function (e) {
            const s = e.target.closest('.star');
            if (!s) return;
            const v = Number(s.getAttribute('data-value')) || 5;
            setStars(v);
        });
        // init from existing data-value
        setStars(Number(starInput.getAttribute('data-value') || 5));
    }

    // Filter reviews by rating -> fetch from API endpoint
    const filterRating = qs('#filter-rating');
    if (filterRating) {
        filterRating.addEventListener('change', async function () {
            const val = this.value;
            try {
                const pid = window.currentProductId || this.dataset.productId;
                const url = `/api/products/${pid}/reviews${val !== 'all' ? '?rating=' + encodeURIComponent(val) : ''}`;
                const resp = await fetch(url, { credentials: 'same-origin' });
                if (!resp.ok) return;
                const data = await resp.json();
                if (!Array.isArray(data.reviews)) return;

                // simple render of reviews list (server will return rendered HTML soon)
                const container = qs('#reviews-list');
                container.innerHTML = '';
                if (data.reviews.length === 0) {
                    container.innerHTML = '<div class="muted">Không có đánh giá nào phù hợp.</div>';
                    return;
                }

                data.reviews.forEach(r => {
                    const div = document.createElement('div');
                    div.className = 'review';
                    div.dataset.id = r.id;
                    div.innerHTML = `
                        <div style="display:flex;align-items:center;gap:12px">
                          <div style="width:48px;height:48px;border-radius:50%;background:var(--border);display:flex;align-items:center;justify-content:center;font-weight:700;color:var(--fg)">${(r.author_name || 'U')[0] || 'U'}</div>
                          <div style="flex:1">
                            <div style="display:flex;align-items:center;gap:12px;justify-content:space-between">
                              <div><strong>${r.author_name || 'Khách'}</strong>${r.verified_purchase ? ' <span class="badge verified">Verified purchase</span>' : ''}<div style="font-size:13px;color:var(--muted)">${new Date(r.created_at).toLocaleString()}</div></div>
                              <div style="display:flex;align-items:center;gap:8px"><div class="review-stars">${'★'.repeat(r.rating) + '☆'.repeat(5 - r.rating)}</div></div>
                            </div>
                            ${r.title ? `<div style="font-weight:700;margin-top:6px">${r.title}</div>` : ''}
                            ${r.body ? `<div style="margin-top:6px;color:var(--muted)">${r.body}</div>` : ''}
                          </div>
                        </div>
                    `;
                    container.appendChild(div);
                });

            } catch (err) { console.error('Filter reviews failed', err); }
        });
    }

    // Helpful up/down vote handlers (delegation)
    document.addEventListener('click', async function (e) {
        const up = e.target.closest('.helpful-up');
        const down = e.target.closest('.helpful-down');
        const el = up || down;
        if (!el) return;
        const id = el.getAttribute('data-id');
        const vote = up ? 'up' : 'down';
        try {
            const resp = await fetch(`/api/reviews/${id}/vote`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ vote }),
                credentials: 'same-origin'
            });
            if (!resp.ok) {
                if (resp.status === 401) window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
                return;
            }
            const data = await resp.json();
            if (data && data.success) {
                // update counts in UI
                const reviewEl = document.querySelector('.review[data-id="' + id + '"]');
                if (reviewEl) {
                    const upC = reviewEl.querySelector('.up-count');
                    const downC = reviewEl.querySelector('.down-count');
                    if (upC && typeof data.up === 'number') upC.textContent = data.up;
                    if (downC && typeof data.down === 'number') downC.textContent = data.down;
                }
            }
        } catch (err) { console.error('Vote failed', err); }
    });

    // contact action is a normal anchor .contact-cta and does not require special JS

    // Question delete menu toggle and deletion
    document.addEventListener('click', function (e) {
        const menuBtn = e.target.closest('.question-menu-btn');
        if (menuBtn) {
            e.stopPropagation();
            const questionId = menuBtn.getAttribute('data-question-id');
            const dropdown = document.querySelector(`.question-menu-dropdown[data-question-id="${questionId}"]`);
            if (dropdown) {
                // toggle dropdown visibility
                const isOpen = dropdown.style.display !== 'none';
                dropdown.style.display = isOpen ? 'none' : 'block';
            }
            return;
        }

        // Close dropdown if clicking outside
        const dropdown = e.target.closest('.question-menu-dropdown');
        if (!dropdown && !e.target.closest('.question-menu-btn')) {
            document.querySelectorAll('.question-menu-dropdown').forEach(d => d.style.display = 'none');
        }
    });

    // Delete question handler
    document.addEventListener('click', async function (e) {
        const deleteBtn = e.target.closest('.question-delete-btn');
        if (!deleteBtn) return;

        const questionId = deleteBtn.getAttribute('data-question-id');
        if (!confirm('Bạn chắc chắn muốn xoá câu hỏi này?')) return;

        try {
            const resp = await fetch(`/api/questions/${questionId}`, {
                method: 'DELETE',
                credentials: 'same-origin'
            });

            const data = await resp.json();
            if (data && data.success) {
                // Remove question from DOM
                const question = document.querySelector(`.question[data-id="${questionId}"]`);
                if (question) {
                    question.style.opacity = '0.5';
                    setTimeout(() => question.remove(), 200);
                }
                if (typeof showToast === 'function') {
                    showToast('Câu hỏi đã được xoá', 'success');
                } else {
                    alert('Câu hỏi đã được xoá');
                }
            } else {
                if (typeof showToast === 'function') {
                    showToast(data?.message || 'Không thể xoá câu hỏi', 'error');
                } else {
                    alert(data?.message || 'Không thể xoá câu hỏi');
                }
            }
        } catch (err) {
            console.error('Error deleting question:', err);
            if (typeof showToast === 'function') {
                showToast('Có lỗi xảy ra', 'error');
            } else {
                alert('Có lỗi xảy ra');
            }
        }
    });

    // FAQ accordion toggles — ensure long answers are fully visible
    document.addEventListener('click', function (e) {
        const q = e.target.closest('.faq-q');
        if (!q) return;
        const parent = q.closest('.faq-item');
        const a = parent && parent.querySelector('.faq-a');
        if (!a) return;

        const willOpen = !a.classList.contains('active');

        if (willOpen) {
            // Make sure element is visible and measure its natural height
            a.style.display = 'block';
            // allow images/fonts to influence height if they are not loaded yet
            const height = a.scrollHeight;
            // start the transition by setting measured height
            a.style.maxHeight = height + 'px';
            a.classList.add('active');
            q.classList.add('active');
            q.setAttribute('aria-expanded', 'true');

            // After transition, clear maxHeight so content can grow naturally
            const onOpenEnd = function () {
                a.style.maxHeight = 'none';
                a.removeEventListener('transitionend', onOpenEnd);
            };
            a.addEventListener('transitionend', onOpenEnd);
        } else {
            // Closing: if maxHeight was 'none', set it to current height to animate
            if (a.style.maxHeight === 'none' || !a.style.maxHeight) {
                a.style.maxHeight = a.scrollHeight + 'px';
                // force reflow so the browser registers the start height
                // eslint-disable-next-line no-unused-expressions
                a.offsetHeight;
            }
            // animate to zero
            a.style.maxHeight = '0px';
            a.classList.remove('active');
            q.classList.remove('active');
            q.setAttribute('aria-expanded', 'false');

            const onCloseEnd = function () {
                // hide after collapsing to keep layout clean
                a.style.display = 'none';
                a.removeEventListener('transitionend', onCloseEnd);
            };
            a.addEventListener('transitionend', onCloseEnd);
        }
    });

})();
