import express from 'express';
import { db, pool } from '../config/database.js';
import { logger } from '../config/logger.js';
import * as dataManager from '../../data/data-manager.js';

const router = express.Router();

// Helper: Get current user ID
function getUserId(req) {
  const user = req.session?.user || req.user || null;
  return user?.id || null;
}

// Helper: Get cart from database if user is logged in, otherwise from session
async function loadCartFromDatabase(userId) {
  if (!userId) return null;
  try {
    const result = await pool.query(
      'SELECT cart_data FROM carts WHERE user_id = $1',
      [userId]
    );
    if (result.rows && result.rows.length > 0 && result.rows[0].cart_data) {
      const cartData = result.rows[0].cart_data;
      if (typeof cartData === 'string') {
        return JSON.parse(cartData);
      }
      return cartData;
    }
    return null;
  } catch (error) {
    console.error('Error loading cart from database:', error);
    return null;
  }
}

// Helper: Get cart from database if user is logged in, otherwise from session
async function getCart(req) {
  if (!req.session) {
    return { items: {}, totalQty: 0, totalCents: 0 };
  }

  if (req.session.user && req.session.user.id) {
    try {
      const dbCart = await loadCartFromDatabase(req.session.user.id);
      if (dbCart) {
        req.session.cart = dbCart;
        req.session.touch();
        return dbCart;
      }
    } catch (error) {
      console.error('Error loading cart from database, falling back to session:', error);
    }
  }

  if (!req.session.cart) {
    req.session.cart = { items: {}, totalQty: 0, totalCents: 0 };
    req.session.touch();
  }

  if (!req.session.cart.items) {
    req.session.cart.items = {};
    req.session.touch();
  }
  if (typeof req.session.cart.totalQty !== 'number') {
    req.session.cart.totalQty = 0;
    req.session.touch();
  }
  if (typeof req.session.cart.totalCents !== 'number') {
    req.session.cart.totalCents = 0;
    req.session.touch();
  }

  return req.session.cart;
}

// Helper: Save cart to database
async function saveCartToDatabase(userId, cart) {
  if (!userId || !cart) return;
  try {
    const checkResult = await pool.query(
      'SELECT id FROM carts WHERE user_id = $1',
      [userId]
    );

    if (checkResult.rows.length > 0) {
      await pool.query(
        `UPDATE carts 
         SET cart_data = $1, updated_at = CURRENT_TIMESTAMP 
         WHERE user_id = $2`,
        [JSON.stringify(cart), userId]
      );
    } else {
      await pool.query(
        `INSERT INTO carts (user_id, cart_data, created_at, updated_at)
         VALUES ($1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
        [userId, JSON.stringify(cart)]
      );
    }
  } catch (error) {
    console.error('Error saving cart to database:', error);
  }
}

// Middleware: Require authentication
function requireAuth(req, res, next) {
  if (!req.session) {
    req.flash('error', 'Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại.');
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }

  const user = req.session?.user || req.user || null;
  if (!user) {
    req.flash('error', 'Vui lòng đăng nhập để tiếp tục');
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }

  next();
}

// API: Add to cart
router.post('/api/cart/add/:productId', requireAuth, async (req, res) => {
  if (!req.session) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }

  try {
    const buyNow = req.body.buy_now === true || req.body.buy_now === 'true' || req.body.buy_now === '1';

    const stmt = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
    const product = await stmt.get(req.params.productId);
    if (!product) {
      return res.json({ success: false, message: 'Sản phẩm không tồn tại' });
    }

    const availableStock = product.stock ?? 0;
    if (availableStock <= 0) {
      return res.json({ success: false, message: 'Sản phẩm đã hết hàng' });
    }

    if (buyNow) {
      req.session.selectedItems = [String(product.id)];
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      return res.json({
        success: true,
        message: 'Đang chuyển đến trang thanh toán...',
        buyNow: true,
        redirect: `/checkout?buy_now=1&product_id=${product.id}`
      });
    }

    const cart = await getCart(req);
    const key = String(product.id);
    if (!cart.items[key]) {
      // Use effective price (apply discount if present) and snapshot into cart item
      const discount = Number(product.discount_percent || 0);
      const effectivePrice = Math.round((product.price_cents || 0) * (100 - discount) / 100);
      const productForCart = { ...product, price_cents: effectivePrice, original_price_cents: product.price_cents };
      cart.items[key] = { product: productForCart, qty: 0 };
    }

    if (cart.items[key].qty + 1 > availableStock) {
      return res.json({ success: false, message: 'Sản phẩm đã hết hàng hoặc không đủ tồn kho' });
    }

    cart.items[key].qty += 1;
    cart.totalQty += 1;
    cart.totalCents += cart.items[key].product.price_cents;
    req.session.cart = cart;
    req.session.touch();

    if (req.session.user && req.session.user.id) {
      await saveCartToDatabase(req.session.user.id, cart);
    }

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session after cart update:', err);
          reject(err);
        } else {
          logger.debug('✅ Session saved after cart update');
          resolve();
        }
      });
    });

    return res.json({
      success: true,
      message: 'Đã thêm vào giỏ hàng',
      cart: {
        totalQty: cart.totalQty,
        totalCents: cart.totalCents
      }
    });
  } catch (error) {
    console.error('Error adding to cart:', error);
    return res.status(500).json({ success: false, message: 'Có lỗi xảy ra khi thêm vào giỏ hàng' });
  }
});

// Add to cart (form submission)
router.post('/cart/add/:productId', requireAuth, async (req, res) => {
  try {
    const stmt = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
    const product = await stmt.get(req.params.productId);
    if (!product) {
      req.flash('error', 'Sản phẩm không tồn tại');
      return res.redirect('back');
    }

    const availableStock = product.stock ?? 0;
    if (availableStock <= 0) {
      req.flash('error', 'Sản phẩm đã hết hàng');
      return res.redirect('back');
    }

    const cart = await getCart(req);
    const key = String(product.id);
    if (!cart.items[key]) {
      const discount = Number(product.discount_percent || 0);
      const effectivePrice = Math.round((product.price_cents || 0) * (100 - discount) / 100);
      const productForCart = { ...product, price_cents: effectivePrice, original_price_cents: product.price_cents };
      cart.items[key] = { product: productForCart, qty: 0 };
    }

    if (cart.items[key].qty + 1 > availableStock) {
      req.flash('error', 'Sản phẩm đã hết hàng hoặc không đủ tồn kho');
      return res.redirect('back');
    }

    cart.items[key].qty += 1;
    cart.totalQty += 1;
    cart.totalCents += cart.items[key].product.price_cents;
    req.session.cart = cart;
    req.session.touch();

    if (req.session.user && req.session.user.id) {
      await saveCartToDatabase(req.session.user.id, cart);
    }

    req.flash('success', 'Đã thêm vào giỏ hàng');

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session after cart add:', err);
          reject(err);
        } else {
          logger.debug('✅ Session saved after cart add');
          resolve();
        }
      });
    });

    if (req.query.buy_now === '1') {
      req.session.selectedItems = [String(product.id)];
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      return res.redirect('/checkout');
    }

    const referer = req.get('Referer') || '/';
    res.redirect(referer);
  } catch (error) {
    console.error('Error adding to cart:', error);
    req.flash('error', 'Có lỗi xảy ra khi thêm vào giỏ hàng');
    res.redirect('back');
  }
});

// Remove from cart
router.post('/cart/remove/:productId', requireAuth, async (req, res) => {
  const cart = await getCart(req);
  const key = String(req.params.productId);
  const entry = cart.items[key];
  if (entry) {
    cart.totalQty = Math.max(0, cart.totalQty - entry.qty);
    cart.totalCents = Math.max(0, cart.totalCents - (entry.qty * entry.product.price_cents));
    delete cart.items[key];
    req.session.cart = cart;
    req.session.touch();

    if (req.session.user && req.session.user.id) {
      await saveCartToDatabase(req.session.user.id, cart);
    }

    req.flash('success', 'Đã xóa sản phẩm khỏi giỏ hàng');

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session after cart delete:', err);
          reject(err);
        } else {
          logger.debug('✅ Session saved after cart delete');
          resolve();
        }
      });
    });
  }
  const referer = req.get('Referer') || '/cart';
  res.redirect(referer.includes('/cart') ? referer : '/cart');
});

// Update cart quantity
router.post('/cart/update/:productId', requireAuth, async (req, res) => {
  try {
    const { quantity } = req.body;
    const newQty = Math.max(0, parseInt(quantity || '0', 10));
    const productId = req.params.productId;

    const stmt = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
    const product = await stmt.get(productId);
    if (!product) {
      req.flash('error', 'Sản phẩm không tồn tại');
      return res.redirect('/cart');
    }

    const cart = await getCart(req);
    const key = String(productId);

    if (newQty === 0) {
      if (cart.items[key]) {
        cart.totalQty -= cart.items[key].qty;
        cart.totalCents -= cart.items[key].qty * cart.items[key].product.price_cents;
        delete cart.items[key];
        req.flash('success', 'Đã xóa sản phẩm khỏi giỏ hàng');
      }
    } else {
      if (newQty > (product.stock ?? 0)) {
        req.flash('error', 'Không đủ tồn kho cho sản phẩm này');
        return res.redirect('/cart');
      }

      if (cart.items[key]) {
        const oldQty = cart.items[key].qty;
        const oldTotal = oldQty * cart.items[key].product.price_cents;

        // Use latest effective price from DB when changing quantity (snapshot it)
        const discount = Number(product.discount_percent || 0);
        const newEffectivePrice = Math.round((product.price_cents || 0) * (100 - discount) / 100);
        const newTotal = newQty * newEffectivePrice;

        cart.totalQty = cart.totalQty - oldQty + newQty;
        cart.totalCents = cart.totalCents - oldTotal + newTotal;
        cart.items[key].qty = newQty;
        cart.items[key].product = { ...product, price_cents: newEffectivePrice, original_price_cents: product.price_cents };
        req.flash('success', 'Đã cập nhật số lượng sản phẩm');
      } else {
        const discount = Number(product.discount_percent || 0);
        const effectivePrice = Math.round((product.price_cents || 0) * (100 - discount) / 100);
        cart.items[key] = { product: { ...product, price_cents: effectivePrice, original_price_cents: product.price_cents }, qty: newQty };
        cart.totalQty += newQty;
        cart.totalCents += newQty * effectivePrice;
        req.flash('success', 'Đã thêm sản phẩm vào giỏ hàng');
      }
    }

    req.session.cart = cart;
    req.session.touch();

    if (req.session.user && req.session.user.id) {
      await saveCartToDatabase(req.session.user.id, cart);
    }

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session after cart update:', err);
          reject(err);
        } else {
          logger.debug('✅ Session saved after cart quantity update');
          resolve();
        }
      });
    });

    res.redirect('/cart');
  } catch (error) {
    console.error('Error updating cart:', error);
    req.flash('error', 'Có lỗi xảy ra khi cập nhật giỏ hàng');
    res.redirect('/cart');
  }
});

// API: Toggle wishlist
router.post('/api/wishlist/toggle/:productId', requireAuth, async (req, res) => {
  try {
    const productId = req.params.productId;
    const userId = getUserId(req);

    const stmt1 = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
    const product = await stmt1.get(productId);
    if (!product) {
      return res.json({ success: false, message: 'Sản phẩm không tồn tại' });
    }

    const stmt2 = db.prepare('SELECT id FROM wishlist WHERE user_id = ? AND product_id = ?');
    const existing = await stmt2.get(userId, productId);

    if (existing) {
      const stmt3 = db.prepare('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?');
      await stmt3.run(userId, productId);

      const wishlistItems = dataManager.findWhere('wishlist', { user_id: userId, product_id: productId });
      wishlistItems.forEach(item => {
        dataManager.deleteItem('wishlist', item.id);
      });

      return res.json({ success: true, message: 'Đã xóa khỏi danh sách yêu thích', action: 'removed' });
    } else {
      const stmt4 = db.prepare('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)');
      await stmt4.run(userId, productId);

      dataManager.addItem('wishlist', {
        id: null,
        user_id: userId,
        product_id: productId,
        created_at: new Date().toISOString()
      });

      return res.json({ success: true, message: 'Đã thêm vào danh sách yêu thích', action: 'added' });
    }
  } catch (err) {
    console.error('Error toggling wishlist:', err);
    return res.json({ success: false, message: 'Lỗi khi thêm vào danh sách yêu thích' });
  }
});

// Add to wishlist (form submission)
router.post('/wishlist/add/:productId', requireAuth, async (req, res) => {
  try {
    const productId = req.params.productId;
    const userId = getUserId(req);

    const stmt1 = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
    const product = await stmt1.get(productId);
    if (!product) {
      req.flash('error', 'Sản phẩm không tồn tại');
      return res.redirect('back');
    }

    const stmt2 = db.prepare('INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)');
    await stmt2.run(userId, productId);

    dataManager.addItem('wishlist', {
      id: null,
      user_id: userId,
      product_id: productId,
      created_at: new Date().toISOString()
    });

    req.flash('success', 'Đã thêm vào danh sách yêu thích');
  } catch (err) {
    if (err.code === '23505' || err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      req.flash('info', 'Sản phẩm đã có trong danh sách yêu thích');
    } else {
      console.error('Error adding to wishlist:', err);
      req.flash('error', 'Lỗi khi thêm vào danh sách yêu thích');
    }
  }

  const referer = req.get('referer') || '/wishlist';
  if (referer.includes('/wishlist')) {
    res.redirect('/wishlist');
  } else {
    res.redirect(referer);
  }
});

// Remove from wishlist
router.post('/wishlist/remove/:productId', requireAuth, async (req, res) => {
  try {
    const productId = req.params.productId;
    const userId = getUserId(req);

    const stmt = db.prepare('DELETE FROM wishlist WHERE user_id = ? AND product_id = ?');
    const result = await stmt.run(userId, productId);

    if (result.changes > 0) {
      const wishlistItems = dataManager.findWhere('wishlist', { user_id: userId, product_id: productId });
      wishlistItems.forEach(item => {
        dataManager.deleteItem('wishlist', item.id);
      });
    }

    if (result.changes > 0) {
      req.flash('success', 'Đã xóa khỏi danh sách yêu thích');
    } else {
      req.flash('info', 'Sản phẩm không có trong danh sách yêu thích');
    }
  } catch (error) {
    console.error('Error removing from wishlist:', error);
    req.flash('error', 'Lỗi khi xóa khỏi danh sách yêu thích');
  }

  res.redirect('/wishlist');
});

// View wishlist
router.get('/wishlist', requireAuth, async (req, res) => {
  try {
    const userId = getUserId(req);
    const stmt = db.prepare(`
      SELECT p.*, w.created_at as added_at
      FROM wishlist w
      JOIN products p ON w.product_id = p.id
      WHERE w.user_id = ? AND p.active = 1
      ORDER BY w.created_at DESC
    `);
    const wishlistItems = await stmt.all(userId);

    res.render('wishlist', { title: 'Danh sách yêu thích - SafeKeyS', wishlistItems });
  } catch (error) {
    console.error('Error loading wishlist:', error);
    req.flash('error', 'Có lỗi xảy ra khi tải danh sách yêu thích');
    res.status(500).render('500', { title: 'Lỗi Server - SafeKeyS' });
  }
});

// View cart
router.get('/cart', requireAuth, async (req, res) => {
  try {
    const cart = await getCart(req);

    let totalQty = 0;
    let totalCents = 0;

    const stmt = db.prepare('SELECT stock, price_cents, title, slug, image FROM products WHERE id=? AND active=1');
    for (const key in cart.items) {
      const item = cart.items[key];
      if (!item || !item.product) {
        delete cart.items[key];
        continue;
      }

      const fresh = await stmt.get(item.product.id);
      if (!fresh) {
        delete cart.items[key];
        continue;
      }

      item.product = {
        id: item.product.id,
        title: fresh.title,
        slug: fresh.slug,
        image: fresh.image,
        price_cents: fresh.price_cents,
        stock: fresh.stock
      };

      totalQty += item.qty;
      totalCents += item.qty * fresh.price_cents;
    }

    cart.totalQty = totalQty;
    cart.totalCents = totalCents;

    res.render('cart', { title: 'Giỏ hàng - SafeKeyS', cart });
  } catch (error) {
    console.error('Error loading cart:', error);
    req.flash('error', 'Có lỗi xảy ra khi tải giỏ hàng');
    res.status(500).render('500', { title: 'Lỗi Server - SafeKeyS' });
  }
});

export default router;
export { getCart, saveCartToDatabase };
