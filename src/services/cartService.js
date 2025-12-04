import fs from 'fs';
import path from 'path';
import { pool } from '../config/database.js';
import { getSetting } from './settingsService.js';
import { logger } from '../config/logger.js';

async function ensureCartsTableExists() {
  try {
    const checkResult = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'carts'
      )
    `);

    if (!checkResult.rows[0].exists) {
      console.log('🔄 Đang tạo bảng carts...');
      await pool.query(`
        CREATE TABLE carts (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          cart_data JSONB NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      await pool.query('CREATE INDEX IF NOT EXISTS idx_carts_user ON carts(user_id)');
      console.log('✅ Đã tạo bảng carts thành công!');
    }
  } catch (error) {
    console.error('Error ensuring carts table exists:', error);
  }
}

async function saveCartToDatabase(userId, cart) {
  if (!userId || !cart) return;
  try {
    const result = await pool.query('SELECT id FROM carts WHERE user_id = $1', [userId]);
    if (result.rows.length > 0) {
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
    if (error.code === '42P01') {
      console.warn('⚠️  Bảng carts chưa tồn tại. Đang tạo bảng...');
      await ensureCartsTableExists();
      await saveCartToDatabase(userId, cart);
      return;
    }
    console.error('Error saving cart to database:', error);
  }
}

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
    if (error.code === '42P01') {
      console.warn('⚠️  Bảng carts chưa tồn tại. Đang tạo bảng...');
      await ensureCartsTableExists();
      return loadCartFromDatabase(userId);
    }
    console.error('Error loading cart from database:', error);
    if (error.message && error.message.includes('user_carts')) {
      console.error('⚠️  PHÁT HIỆN: Code vẫn đang tìm bảng user_carts. Có thể server chưa restart hoặc có code cũ đang chạy.');
    }
    return null;
  }
}

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

  // Recalculate totals (including originalTotalCents and discountCents) from the item snapshots
  try {
    let runningTotal = 0;
    let runningOriginalTotal = 0;
    let runningQty = 0;
    const items = req.session.cart.items || {};
    Object.keys(items).forEach(k => {
      const entry = items[k];
      const qty = entry.qty || 0;
      const price = entry.product && typeof entry.product.price_cents === 'number' ? entry.product.price_cents : 0;
      const orig = entry.product && typeof entry.product.original_price_cents === 'number' ? entry.product.original_price_cents : price;
      runningTotal += qty * price;
      runningOriginalTotal += qty * orig;
      runningQty += qty;
    });

    req.session.cart.totalCents = runningTotal;
    req.session.cart.originalTotalCents = runningOriginalTotal;
    req.session.cart.discountCents = Math.max(0, runningOriginalTotal - runningTotal);

    // Compute VAT and grand total (VAT percent is configurable in settings)
    try {
      const vatPercentStr = await getSetting('vat_percent', '10');
      const vatPercent = Math.max(0, Math.min(100, parseInt(String(vatPercentStr || '0'), 10) || 0));
      const vatCents = Math.round(req.session.cart.totalCents * vatPercent / 100);
      req.session.cart.vatPercent = vatPercent;
      req.session.cart.vatCents = vatCents;
      req.session.cart.grandTotalCents = req.session.cart.totalCents + vatCents;
    } catch (e) {
      req.session.cart.vat_percent = 0;
      req.session.cart.vat_cents = 0;
      req.session.cart.grandTotalCents = req.session.cart.totalCents;
    }
    req.session.cart.totalQty = runningQty;
    req.session.touch();
  } catch (calcErr) {
    // If anything fails here, keep the session values as-is
    console.error('Error computing cart totals in service:', calcErr);
  }

  return req.session.cart;
}

export {
  getCart,
  saveCartToDatabase,
  loadCartFromDatabase,
  ensureCartsTableExists
};



