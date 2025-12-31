// AJAX handler for product review submissions
(function () {
    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function showMessage(el, text, isError) {
        if (!el) return;
        el.textContent = text;
        el.classList.remove('success', 'error');
        el.classList.add(isError ? 'error' : 'success');
        el.style.display = 'block';
        setTimeout(() => { el.style.display = 'none'; }, 5000);
    }

    function createReviewElement(review) {
        var container = document.createElement('div');
        container.className = 'review-item';

        var header = document.createElement('div');
        header.className = 'review-header';
        header.innerHTML = '<strong>' + escapeHtml(review.author_name || 'Người dùng') + '</strong>' +
            ' <span class="muted">' + (review.created_at || '') + '</span>';

        var body = document.createElement('div');
        body.className = 'review-body';
        body.innerHTML = '<p>' + escapeHtml(review.body || '') + '</p>';

        container.appendChild(header);
        container.appendChild(body);

        if (review.images && Array.isArray(review.images) && review.images.length) {
            var imgs = document.createElement('div');
            imgs.className = 'review-images row';
            review.images.forEach(function (src) {
                var img = document.createElement('img');
                img.src = src;
                img.alt = 'review image';
                img.style.maxWidth = '120px';
                img.style.marginRight = '8px';
                imgs.appendChild(img);
            });
            container.appendChild(imgs);
        }

        return container;
    }

    function getProductId() {
        // Try meta tag, data attribute, or URL
        var meta = document.querySelector('meta[name="product-id"]');
        if (meta && meta.content) return meta.content;
        var el = document.querySelector('#review-form');
        if (el && el.dataset && el.dataset.productId) return el.dataset.productId;
        var m = window.location.pathname.match(/\/product\/(\d+)/);
        return m ? m[1] : null;
    }

    document.addEventListener('DOMContentLoaded', function () {
        var form = document.getElementById('review-form');
        if (!form) return;
        var messageEl = document.getElementById('review-form-message');
        var reviewsList = document.getElementById('reviews-list');

        form.addEventListener('submit', function (e) {
            e.preventDefault();
            var submitBtn = document.getElementById('submit-review-btn') || form.querySelector('button[type=submit]');
            if (submitBtn) submitBtn.disabled = true;

            var productId = getProductId();
            if (!productId) {
                showMessage(messageEl, 'Không xác định được sản phẩm.', true);
                if (submitBtn) submitBtn.disabled = false;
                return;
            }

            var fd = new FormData(form);
            // include _csrf if present as header as well
            var csrfInput = form.querySelector('input[name="_csrf"]');
            var csrf = csrfInput ? csrfInput.value : '';

            fetch('/product/' + encodeURIComponent(productId) + '/review', {
                method: 'POST',
                body: fd,
                credentials: 'same-origin',
                headers: csrf ? { 'x-csrf-token': csrf } : undefined
            }).then(function (res) {
                return res.json().catch(function () { return { success: false, message: 'Invalid server response' }; });
            }).then(function (json) {
                if (!json || !json.success) {
                    showMessage(messageEl, json && json.message ? json.message : 'Gửi đánh giá thất bại', true);
                    if (submitBtn) submitBtn.disabled = false;
                    return;
                }

                var reviewElem = createReviewElement(json.review || {});
                if (reviewsList) reviewsList.insertBefore(reviewElem, reviewsList.firstChild);
                else form.parentNode.insertBefore(reviewElem, form);

                showMessage(messageEl, json.message || 'Gửi đánh giá thành công', false);
                form.reset();
                // reset star inputs if any
                var stars = form.querySelectorAll('.star-input');
                stars.forEach(function (s) { s.checked = false; });
                if (submitBtn) submitBtn.disabled = false;
            }).catch(function (err) {
                showMessage(messageEl, 'Lỗi kết nối. Vui lòng thử lại.', true);
                if (submitBtn) submitBtn.disabled = false;
            });
        });
    });
})();
