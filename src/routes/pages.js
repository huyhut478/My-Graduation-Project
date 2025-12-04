import express from 'express';
import { uploadReview } from '../config/uploads.js';
import * as reviewService from '../services/reviewService.js';

const router = express.Router();

/**
 * Page routes - home, catalog, categories, product detail
 */

export function createExcerpt(content, maxLength = 200) {
    if (!content) return '';
    const text = content.replace(/<[^>]*>/g, '').replace(/\n/g, ' ').trim();
    if (text.length <= maxLength) return text;
    const truncated = text.substring(0, maxLength);
    const lastSpace = truncated.lastIndexOf(' ');
    return lastSpace > 0 ? truncated.substring(0, lastSpace) + '...' : truncated + '...';
}

export function setupPageRoutes(app, { pool, db, getSetting, logger }) {
    // Home page
    app.get('/', async (req, res) => {
        try {
            const q = (req.query.q || '').trim();
            const sort = req.query.sort || 'newest';
            const category = req.query.category || '';
            const priceRange = req.query.price || '';

            const homepageSettings = {
                hero_title: await getSetting('homepage_hero_title', 'SafeKeyS'),
                hero_subtitle: await getSetting('homepage_hero_subtitle', 'Mua key phần mềm, game nhanh chóng - Uy tín - Nhanh gọn - Hỗ trợ 24/7'),
                hero_features: await getSetting('homepage_hero_features', 'Thanh toán an toàn•Giao key ngay lập tức•Bảo hành chính hãng'),
                carousel_title: await getSetting('homepage_carousel_title', 'Sản phẩm nổi bật'),
                carousel_subtitle: await getSetting('homepage_carousel_subtitle', 'Khám phá những sản phẩm hot nhất hiện nay')
            };

            const categoriesResult = await pool.query(`
        SELECT c.*, COUNT(p.id) as product_count
        FROM categories c
        LEFT JOIN products p ON p.category_id = c.id AND p.active = 1
        GROUP BY c.id
        ORDER BY c.name ASC
      `);
            const categories = categoriesResult.rows;

            const featuredProductsResult = await pool.query(`
        SELECT DISTINCT * FROM products 
        WHERE active = 1 AND featured = 1 
        ORDER BY id DESC 
        LIMIT 20
      `);
            const featuredProducts = featuredProductsResult.rows;

            let products = [];
            let whereConditions = ['active = 1'];
            let params = [];
            let paramIndex = 1;

            if (q) {
                whereConditions.push(`(title ILIKE $${paramIndex} OR description ILIKE $${paramIndex + 1})`);
                params.push(`%${q}%`, `%${q}%`);
                paramIndex += 2;
            }

            if (category) {
                whereConditions.push(`category_id = (SELECT id FROM categories WHERE slug = $${paramIndex})`);
                params.push(category);
                paramIndex++;
            }

            if (priceRange) {
                const [min, max] = priceRange.split('-').map(Number);
                if (min !== undefined && max !== undefined) {
                    whereConditions.push(`price_cents BETWEEN $${paramIndex} AND $${paramIndex + 1}`);
                    params.push(min * 100, max * 100);
                    paramIndex += 2;
                } else if (min !== undefined) {
                    whereConditions.push(`price_cents >= $${paramIndex}`);
                    params.push(min * 100);
                    paramIndex++;
                }
            }

            let orderBy = 'ORDER BY ';
            switch (sort) {
                case 'oldest':
                    orderBy += 'id ASC';
                    break;
                case 'price-low':
                    orderBy += 'price_cents ASC';
                    break;
                case 'price-high':
                    orderBy += 'price_cents DESC';
                    break;
                case 'name':
                    orderBy += 'title ASC';
                    break;
                case 'stock':
                    orderBy += 'stock DESC, id DESC';
                    break;
                case 'newest':
                default:
                    orderBy += 'id DESC';
                    break;
            }

            const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';
            const limitClause = !q && !category && !priceRange ? 'LIMIT 12' : '';

            let query = `SELECT * FROM products ${whereClause} ${orderBy}`;
            if (limitClause) {
                query += ` ${limitClause}`;
            }

            const productsResult = params.length > 0
                ? await pool.query(query, params)
                : await pool.query(query);
            products = productsResult.rows;

            let latestNews = [];
            if (!q && !category && !priceRange) {
                try {
                    const newsResult = await pool.query(`
            SELECT id, title, slug, content, COALESCE(excerpt, '') as excerpt, created_at, thumbnail, COALESCE(author, '') as author 
            FROM news 
            WHERE published = 1 
            ORDER BY id DESC 
            LIMIT 6
          `);
                    latestNews = newsResult.rows.map(post => ({
                        ...post,
                        excerpt: (post.excerpt && post.excerpt.trim()) ? post.excerpt : createExcerpt(post.content || '', 150),
                        readingTime: Math.max(1, Math.round((post.content || '').split(/\s+/).filter(Boolean).length / 200)),
                        author: post.author && post.author.trim() ? post.author : null
                    }));
                } catch (newsError) {
                    console.error('⚠️ Lỗi khi lấy tin tức cho trang chủ:', newsError);
                    latestNews = [];
                }
            }

            const structuredData = {
                "@context": "https://schema.org",
                "@type": "WebSite",
                "name": "SafeKeyS",
                "url": req.protocol + "://" + req.get('host'),
                "description": "Cửa hàng chuyên cung cấp key bản quyền phần mềm, game và thẻ nạp uy tín",
                "potentialAction": {
                    "@type": "SearchAction",
                    "target": req.protocol + "://" + req.get('host') + "/?q={search_term_string}",
                    "query-input": "required name=search_term_string"
                }
            };

            // Provide wishlist ids to template when user is logged in
            let wishlistIds = [];
            if (req.session && req.session.user && req.session.user.id) {
                try {
                    const wishRes = await pool.query('SELECT product_id FROM wishlist WHERE user_id = $1', [req.session.user.id]);
                    wishlistIds = wishRes.rows.map(r => r.product_id);
                } catch (err) {
                    logger.warn('Could not load wishlist ids for home route', err);
                    wishlistIds = [];
                }
            }

            res.render('home', {
                title: 'SafeKeyS',
                categories,
                products,
                featuredProducts: featuredProducts || [],
                latestNews,
                homepageSettings,
                q,
                sort,
                category,
                priceRange,
                structuredData,
                description: 'Cửa hàng chuyên cung cấp key bản quyền phần mềm, game và thẻ nạp uy tín, nhanh chóng. Giao hàng tự động trong 5 phút, hỗ trợ 24/7.',
                canonical: req.protocol + "://" + req.get('host') + req.originalUrl,
                wishlistIds
            });
        } catch (error) {
            console.error('❌ Error in home route:', error);
            console.error('Error stack:', error.stack);
            req.flash('error', 'Có lỗi xảy ra khi tải trang chủ');
            res.status(500).render('500', {
                title: 'Lỗi Server - SafeKeyS',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    });

    // API: Filter products
    app.get('/api/products/filter', async (req, res) => {
        try {
            const q = (req.query.q || '').trim();
            const sort = req.query.sort || 'newest';
            const category = req.query.category || '';
            const priceRange = req.query.price || '';

            let products = [];
            let whereConditions = ['active=1'];
            let params = [];

            if (q) {
                whereConditions.push('(title LIKE ? OR description LIKE ?)');
                params.push(`%${q}%`, `%${q}%`);
            }

            if (category) {
                whereConditions.push('category_id = (SELECT id FROM categories WHERE slug = ?)');
                params.push(category);
            }

            if (priceRange) {
                const [min, max] = priceRange.split('-').map(Number);
                if (min !== undefined && max !== undefined) {
                    whereConditions.push('price_cents BETWEEN ? AND ?');
                    params.push(min * 100, max * 100);
                } else if (min !== undefined) {
                    whereConditions.push('price_cents >= ?');
                    params.push(min * 100);
                }
            }

            let orderBy = 'ORDER BY ';
            switch (sort) {
                case 'oldest':
                    orderBy += 'id ASC';
                    break;
                case 'price-low':
                    orderBy += 'price_cents ASC';
                    break;
                case 'price-high':
                    orderBy += 'price_cents DESC';
                    break;
                case 'name':
                    orderBy += 'title ASC';
                    break;
                case 'stock':
                    orderBy += 'stock DESC, id DESC';
                    break;
                case 'newest':
                default:
                    orderBy += 'id DESC';
                    break;
            }

            const whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';
            const limitClause = !q && !category && !priceRange ? 'LIMIT 12' : '';

            const query = `SELECT * FROM products ${whereClause} ${orderBy} ${limitClause}`;
            const stmt1 = db.prepare(query);
            products = await stmt1.all(...params);

            const csrfToken = res.locals.csrfToken || '';
            const isLoggedIn = req.session && req.session.user;

            // Load wishlist state for logged-in user so we can render heart state
            let wishlistSet = new Set();
            if (isLoggedIn && req.session.user && req.session.user.id) {
                try {
                    const wishRes = await pool.query('SELECT product_id FROM wishlist WHERE user_id = $1', [req.session.user.id]);
                    wishlistSet = new Set(wishRes.rows.map(r => Number(r.product_id)));
                } catch (err) {
                    logger.warn('Could not load wishlist for pages filter API', err);
                    wishlistSet = new Set();
                }
            }

            let html = '';
            if (products.length === 0) {
                html = `
        <div class="no-products">
          <div class="no-products-icon">🔍</div>
          <h3>Không tìm thấy sản phẩm</h3>
          <p class="muted">Thử thay đổi bộ lọc hoặc tìm kiếm với từ khóa khác.</p>
        </div>
      `;
            } else {
                products.forEach(p => {
                    const priceVnd = (p.price_cents / 100).toLocaleString('vi-VN');
                    const stockBadge = p.stock > 0
                        ? `<span class="in-stock">✅ Còn hàng (${p.stock})</span>`
                        : '<span class="out-of-stock">❌ Hết hàng</span>';
                    const escapedTitle = (p.title || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
                    const escapedDesc = ((p.description || '').slice(0, 80)).replace(/"/g, '&quot;').replace(/'/g, '&#39;');

                    html += `
          <div class="product-card">
            <div class="product-image">
              <img src="${(p.image || '/img/placeholder.jpg').replace(/"/g, '&quot;')}" alt="${escapedTitle}" loading="lazy" decoding="async">
              <div class="product-overlay">
                <a href="/product/${p.slug}" class="btn quick-view">Xem chi tiết</a>
              </div>
            </div>
            <div class="product-info">
              <h3 class="product-title">
                <a href="/product/${p.slug}">${escapedTitle}</a>
              </h3>
              <p class="product-description">${escapedDesc}${(p.description && p.description.length > 80) ? '...' : ''}</p>
              <div class="product-stock">${stockBadge}</div>
              <div class="product-price">
                <span class="price">${priceVnd} VND</span>
              </div>
              <div class="product-actions">
                <button class="btn primary" onclick="addToCart(${p.id}, false, '${csrfToken}')" ${p.stock === 0 ? 'disabled' : ''}>
                  ${p.stock === 0 ? 'Hết hàng' : 'Thêm vào giỏ'}
                </button>
                ${isLoggedIn ? `
                  <form class="wishlist-form" onsubmit="event.preventDefault(); toggleWishlist(${p.id}, '${csrfToken}');">
                                    <button type="submit" class="btn wishlist-btn ${wishlistSet.has(Number(p.id)) ? 'active' : ''}" title="Thêm vào yêu thích" aria-pressed="${wishlistSet.has(Number(p.id)) ? 'true' : 'false'}">
                                            <svg class="icon-heart" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41 0.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" fill="currentColor"></path></svg>
                                        </button>
                  </form>
                ` : ''}
              </div>
            </div>
          </div>
        `;
                });
            }

            res.json({
                success: true,
                html: html,
                count: products.length
            });
        } catch (error) {
            console.error('Error in filter API:', error);
            res.status(500).json({ success: false, message: 'Có lỗi xảy ra khi lọc sản phẩm' });
        }
    });

    // Category page
    app.get('/category/:slug', async (req, res) => {
        try {
            const stmt1 = db.prepare('SELECT * FROM categories WHERE slug = ?');
            const category = await stmt1.get(req.params.slug);
            if (!category) {
                req.flash('error', 'Danh mục không tồn tại');
                return res.status(404).render('404');
            }

            const stmt2 = db.prepare(`
        SELECT * FROM products 
        WHERE active=1 AND category_id=? 
        ORDER BY id DESC
      `);
            const products = await stmt2.all(category.id);

            // Provide wishlist ids to category template so hearts render correctly
            let wishlistIds = [];
            if (req.session && req.session.user && req.session.user.id) {
                try {
                    const wishRes = await pool.query('SELECT product_id FROM wishlist WHERE user_id = $1', [req.session.user.id]);
                    wishlistIds = wishRes.rows.map(r => r.product_id);
                } catch (err) {
                    logger.warn('Could not load wishlist ids for category route', err);
                    wishlistIds = [];
                }
            }

            res.render('category', { title: category.name + ' - SafeKeyS', category, products: products || [], wishlistIds });
        } catch (error) {
            console.error('Error in category route:', error);
            req.flash('error', 'Có lỗi xảy ra khi tải danh mục');
            res.status(500).render('500', { title: 'Lỗi Server - SafeKeyS' });
        }
    });

    // Categories page
    app.get('/categories', async (req, res) => {
        try {
            const stmt = db.prepare(`
        SELECT c.*, COUNT(p.id) as product_count
        FROM categories c
        LEFT JOIN products p ON p.category_id = c.id AND p.active = 1
        GROUP BY c.id
        ORDER BY c.name ASC
      `);
            const categories = await stmt.all();
            res.render('categories', { title: 'Danh mục - SafeKeyS', categories });
        } catch (error) {
            console.error('Error in categories route:', error);
            req.flash('error', 'Có lỗi xảy ra khi tải danh mục');
            res.status(500).render('500', { title: 'Lỗi Server - SafeKeyS' });
        }
    });

    // Product detail page
    app.get('/product/:slug', async (req, res) => {
        try {
            const stmt1 = db.prepare('SELECT * FROM products WHERE slug=? AND active=1');
            const product = await stmt1.get(req.params.slug);
            if (!product) return res.status(404).render('404');

            let category = null;
            if (product.category_id) {
                const stmt2 = db.prepare('SELECT * FROM categories WHERE id=?');
                category = await stmt2.get(product.category_id);
            }

            const structuredData = {
                "@context": "https://schema.org",
                "@type": "Product",
                "name": product.title,
                "description": product.description || '',
                "image": product.image || req.protocol + "://" + req.get('host') + "/img/placeholder.jpg",
                "offers": {
                    "@type": "Offer",
                    "price": (product.price_cents / 100).toFixed(2),
                    "priceCurrency": "VND",
                    "availability": product.stock > 0 ? "https://schema.org/InStock" : "https://schema.org/OutOfStock"
                }
            };

            // Ensure reviews table exists and load reviews for this product
            try { await reviewService.ensureReviewsTableExists(pool); } catch (e) { /* ignore */ }
            const reviews = await reviewService.getReviewsByProduct(pool, product.id, { limit: 50 });
            const reviewsSummary = await reviewService.getReviewSummary(pool, product.id);

            // Determine whether current user purchased this product and whether they've already reviewed
            const userId = req.session?.user?.id || null;
            let userHasPurchased = false;
            let userHasReviewed = false;
            if (userId) {
                try {
                    const purchased = await pool.query(`
                        SELECT 1 FROM order_items oi JOIN orders o ON o.id = oi.order_id
                        WHERE oi.product_id = $1 AND o.user_id = $2 AND o.status IN ('paid','completed') LIMIT 1
                    `, [product.id, userId]);
                    userHasPurchased = purchased.rowCount > 0;
                } catch (e) {
                    userHasPurchased = false;
                }

                try {
                    userHasReviewed = await reviewService.hasUserReviewed(pool, product.id, userId);
                } catch (e) { userHasReviewed = false; }
            }
            const userCanReview = !!(userId && userHasPurchased && !userHasReviewed);

            // Determine whether this product is favorited by current user
            let isFavorited = false;
            if (req.session && req.session.user && req.session.user.id) {
                try {
                    const favRes = await pool.query('SELECT 1 FROM wishlist WHERE user_id = $1 AND product_id = $2 LIMIT 1', [req.session.user.id, product.id]);
                    isFavorited = favRes.rowCount > 0;
                } catch (err) {
                    logger.warn('Could not determine favorite for product page', err);
                    isFavorited = false;
                }
            }

            res.render('product', {
                title: product.title + ' - SafeKeyS',
                product,
                category,
                reviews,
                reviewsSummary,
                structuredData,
                description: product.description || `Mua ${product.title} với giá tốt nhất tại SafeKeyS`,
                canonical: req.protocol + "://" + req.get('host') + req.originalUrl,
                ogUrl: req.protocol + "://" + req.get('host') + req.originalUrl,
                ogImage: product.image || req.protocol + "://" + req.get('host') + "/img/placeholder.jpg",
                isFavorited,
                userCanReview,
                userHasPurchased,
                userHasReviewed
            });
        } catch (error) {
            console.error('Error in product route:', error);
            req.flash('error', 'Có lỗi xảy ra khi tải sản phẩm');
            res.status(500).render('500', { title: 'Lỗi Server - SafeKeyS' });
        }
    });

    // Submit a product review (accept images)
    app.post('/product/:id/review', uploadReview.array('images', 3), async (req, res) => {
        try {
            const productId = Number(req.params.id);
            if (isNaN(productId)) return res.redirect('back');

            await reviewService.ensureReviewsTableExists(pool);

            const rating = Math.max(1, Math.min(5, Number(req.body.rating || 5)));
            const title = (req.body.title || '').trim();
            const body = (req.body.body || '').trim();
            const images = (req.files || []).map(f => `/img/reviews/${f.filename}`);

            const userId = req.session?.user?.id || null;
            // Must be logged in
            if (!userId) {
                req.flash('error', 'Bạn cần đăng nhập và đã mua sản phẩm để gửi đánh giá');
                return res.redirect('back');
            }

            let verified = false;
            if (userId) {
                try {
                    const purchased = await pool.query(`
                      SELECT 1 FROM order_items oi JOIN orders o ON o.id = oi.order_id
                      WHERE oi.product_id = $1 AND o.user_id = $2 AND o.status IN ('paid','completed') LIMIT 1
                    `, [productId, userId]);
                    verified = purchased.rowCount > 0;
                } catch (e) {
                    // ignore
                }
            }

            if (!verified) {
                req.flash('error', 'Chỉ những người đã mua sản phẩm mới được gửi đánh giá');
                return res.redirect('back');
            }

            // Prevent duplicates
            const already = await reviewService.hasUserReviewed(pool, productId, userId);
            if (already) {
                req.flash('error', 'Bạn chỉ được gửi một đánh giá cho mỗi sản phẩm');
                return res.redirect('back');
            }

            const authorName = req.session?.user?.name || req.body.author_name || 'Khách';

            const newReview = await reviewService.addReview(pool, {
                product_id: productId,
                user_id: userId,
                author_name: authorName,
                rating,
                title: title || null,
                body: body || null,
                images,
                verified_purchase: verified
            });

            req.flash('success', 'Cảm ơn — đánh giá của bạn đã được gửi.');
            const referer = req.get('Referer') || '/';
            res.redirect(referer);
        } catch (err) {
            console.error('Error creating review', err);
            req.flash('error', 'Không thể gửi đánh giá — vui lòng thử lại');
            res.redirect('back');
        }
    });

    // API: fetch reviews for a product (optionally filter by rating)
    app.get('/api/products/:productId/reviews', async (req, res) => {
        try {
            const productId = Number(req.params.productId);
            if (isNaN(productId)) return res.status(400).json({ reviews: [] });
            await reviewService.ensureReviewsTableExists(pool);
            const rating = req.query.rating ? Number(req.query.rating) : null;
            const reviews = await reviewService.getReviewsByProduct(pool, productId, { rating });
            res.json({ reviews });
        } catch (err) {
            console.error('Error loading reviews', err);
            res.status(500).json({ reviews: [] });
        }
    });

    // API: vote helpful on a review
    app.post('/api/reviews/:id/vote', async (req, res) => {
        try {
            if (!req.session || !req.session.user || !req.session.user.id) return res.status(401).json({ success: false });
            const id = Number(req.params.id);
            if (isNaN(id)) return res.status(400).json({ success: false });
            const { vote } = req.body || {};
            if (!['up', 'down'].includes(vote)) return res.status(400).json({ success: false });
            const updated = await reviewService.incrementHelpful(pool, id, vote);
            res.json({ success: true, up: updated.helpful_up, down: updated.helpful_down });
        } catch (err) {
            console.error('Error voting', err);
            res.status(500).json({ success: false });
        }
    });

    // API: vote up/down helpful
    app.post('/api/reviews/:id/vote', async (req, res) => {
        try {
            if (!req.session || !req.session.user) return res.status(401).json({ success: false, message: 'Authentication required' });
            const id = Number(req.params.id);
            if (isNaN(id)) return res.status(400).json({ success: false });
            const vote = (req.body && req.body.vote) || (req.query && req.query.vote) || null;
            if (!['up', 'down'].includes(vote)) return res.status(400).json({ success: false, message: 'Invalid vote' });

            const updated = await reviewService.incrementHelpful(pool, id, vote);
            res.json({ success: true, up: updated.helpful_up, down: updated.helpful_down });
        } catch (err) {
            console.error('Error voting review', err);
            res.status(500).json({ success: false });
        }
    });
}

export default router;
