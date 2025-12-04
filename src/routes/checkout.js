import { Router } from 'express';
import https from 'https';
import crypto from 'crypto';
import { db, pool } from '../config/database.js';
import { logger } from '../config/logger.js';
import { dataManager } from '../../data/data-manager.js';
import { getSetting } from '../services/settingsService.js';
import { getCart, saveCartToDatabase } from './cart.js';

const router = Router();

// Middleware
function requireAuth(req, res, next) {
  if (!req.session?.user) {
    req.flash('error', 'Vui lòng đăng nhập để tiếp tục');
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

function getUserId(req) {
  return req.session?.user?.id || null;
}

// MoMo Configuration (Test Environment)
const MOMO_ACCESS_KEY = "F8BBA842ECF85";
const MOMO_SECRET_KEY = "K951B6PE1waDMi640xX08PD3vg6EkVlz";
const MOMO_PARTNER_CODE = "MOMO";
const MOMO_REQUEST_TYPE = "captureWallet";
const MOMO_LANG = "vi";

// Helper functions
function getBaseUrl(req) {
  return `${req.protocol}://${req.get('host')}`;
}

// GET /checkout - Display checkout page
router.get('/checkout', requireAuth, async (req, res) => {
  try {
    // Handle buy_now parameter - create temporary cart for checkout (bypass cart check)
    if (req.query.buy_now === '1' && req.query.product_id) {
      // Buy now: create temporary cart with only this product
      const productId = req.query.product_id;
      const stmt = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
      const product = await stmt.get(productId);

      if (product && (product.stock ?? 0) > 0) {
        // Create temporary cart for checkout (not saved to session.cart)
        // Apply discount if present and keep original price so checkout shows promotion
        const discountPercent = Number(product.discount_percent || 0);
        const effectivePrice = Math.round((product.price_cents || 0) * (100 - discountPercent) / 100);

        const tempCart = {
          items: {
            [String(productId)]: {
              product: {
                id: product.id,
                title: product.title,
                slug: product.slug,
                image: product.image,
                price_cents: effectivePrice,
                original_price_cents: product.price_cents,
                discount_percent: discountPercent,
                stock: product.stock
              },
              qty: 1
            }
          },
          totalQty: 1,
          totalCents: effectivePrice,
          originalTotalCents: product.price_cents,
          discountCents: Math.max(0, product.price_cents - effectivePrice)
        };

        // Set selectedItems for this product
        req.session.selectedItems = [String(productId)];

        // Compute VAT for tempCart (use site setting default 10%)
        try {
          const vatPercentStrTmp = await getSetting('vat_percent', '10');
          const vatPercentTmp = Math.max(0, Math.min(100, parseInt(String(vatPercentStrTmp || '0'), 10) || 0));
          const vatCentsTmp = Math.round(tempCart.totalCents * vatPercentTmp / 100);
          tempCart.vatPercent = vatPercentTmp;
          tempCart.vatCents = vatCentsTmp;
          tempCart.grandTotalCents = tempCart.totalCents + vatCentsTmp;
        } catch (e) {
          tempCart.vatPercent = 0;
          tempCart.vatCents = 0;
          tempCart.grandTotalCents = tempCart.totalCents;
        }

        // Render checkout with temporary cart
        const insufficient = [];
        res.render('checkout', {
          title: 'Xác nhận thanh toán - SafeKeyS',
          cart: tempCart,
          insufficient,
          buyNow: true
        });
        return;
      } else {
        req.flash('error', 'Sản phẩm không tồn tại hoặc đã hết hàng');
        return res.redirect('/');
      }
    }

    // Normal checkout flow (from cart)
    const cart = await getCart(req);
    if (cart.totalQty === 0) {
      req.flash('error', 'Giỏ hàng trống');
      return res.redirect('/cart');
    }

    // Filter items based on selected_items from session
    const selectedItems = req.session.selectedItems || [];
    const filteredCart = {
      items: {},
      totalQty: 0,
      totalCents: 0
    };

    if (selectedItems.length > 0) {
      // Only include selected items
      for (const productId of selectedItems) {
        const key = String(productId);
        if (cart.items[key]) {
          filteredCart.items[key] = cart.items[key];
          // Ensure each selected item has a proper effective price/original price snapshot
          const productEntry = cart.items[key];
          if (productEntry) {
            // If product snapshot already contains original_price_cents, trust it; otherwise refresh from DB
            if (!productEntry.product.original_price_cents) {
              const pStmt = db.prepare('SELECT price_cents, discount_percent FROM products WHERE id=?');
              const fresh = await pStmt.get(productEntry.product.id);
              const dbPrice = fresh ? (fresh.price_cents || 0) : (productEntry.product.price_cents || 0);
              const discount = fresh ? Number(fresh.discount_percent || 0) : Number(productEntry.product.discount_percent || 0);
              const effective = Math.round(dbPrice * (100 - discount) / 100);
              productEntry.product.price_cents = effective;
              productEntry.product.original_price_cents = dbPrice;
              productEntry.product.discount_percent = discount;
            }

            filteredCart.totalQty += productEntry.qty;
            filteredCart.totalCents += productEntry.qty * productEntry.product.price_cents;
          }
        }
      }
    } else {
      // If no selection, use all items (backward compatibility)
      // Use all items; ensure we normalize price snapshots and compute totals
      let runningTotal = 0;
      let runningOriginalTotal = 0;
      for (const k of Object.keys(cart.items)) {
        const entry = cart.items[k];
        // refresh DB price & discount if snapshot missing original_price_cents
        if (!entry.product.original_price_cents) {
          const pStmt = db.prepare('SELECT price_cents, discount_percent FROM products WHERE id=?');
          const fresh = await pStmt.get(entry.product.id);
          const dbPrice = fresh ? (fresh.price_cents || 0) : (entry.product.price_cents || 0);
          const discount = fresh ? Number(fresh.discount_percent || 0) : Number(entry.product.discount_percent || 0);
          const effective = Math.round(dbPrice * (100 - discount) / 100);
          entry.product.price_cents = effective;
          entry.product.original_price_cents = dbPrice;
          entry.product.discount_percent = discount;
        }

        runningTotal += entry.qty * entry.product.price_cents;
        runningOriginalTotal += entry.qty * (entry.product.original_price_cents || entry.product.price_cents);
      }
      filteredCart.items = cart.items;
      filteredCart.totalQty = cart.totalQty;
      filteredCart.totalCents = runningTotal;
      filteredCart.originalTotalCents = runningOriginalTotal;
      filteredCart.discountCents = Math.max(0, runningOriginalTotal - runningTotal);
    }

    // Compute VAT for filteredCart
    try {
      const vatPercentStrFC = await getSetting('vat_percent', '10');
      const vatPercentFC = Math.max(0, Math.min(100, parseInt(String(vatPercentStrFC || '0'), 10) || 0));
      const vatCentsFC = Math.round(filteredCart.totalCents * vatPercentFC / 100);
      filteredCart.vatPercent = vatPercentFC;
      filteredCart.vatCents = vatCentsFC;
      filteredCart.grandTotalCents = filteredCart.totalCents + vatCentsFC;
    } catch (e) {
      filteredCart.vatPercent = 0;
      filteredCart.vatCents = 0;
      filteredCart.grandTotalCents = filteredCart.totalCents;
    }

    if (filteredCart.totalQty === 0) {
      req.flash('error', 'Vui lòng chọn ít nhất một sản phẩm để thanh toán');
      return res.redirect('/cart');
    }

    // Check stock availability for selected items
    const insufficient = [];
    const stmt = db.prepare('SELECT stock FROM products WHERE id=?');
    for (const { product, qty } of Object.values(filteredCart.items)) {
      const fresh = await stmt.get(product.id);
      if (!fresh || qty > (fresh.stock ?? 0)) insufficient.push(product.title);
    }

    res.render('checkout', { title: 'Xác nhận thanh toán - SafeKeyS', cart: filteredCart, insufficient });
  } catch (error) {
    console.error('Error in checkout route:', error);
    req.flash('error', 'Có lỗi xảy ra khi tải trang thanh toán');
    res.status(500).render('500', { title: 'Lỗi Server - SafeKeyS' });
  }
});

// POST /checkout - Handle item selection for checkout
router.post('/checkout', requireAuth, async (req, res) => {
  const cart = await getCart(req);

  // Debug: log received data
  logger.debug('POST /checkout - req.body:', req.body);
  logger.debug('POST /checkout - req.body.selected_items:', req.body.selected_items);

  // Handle selected_items - can be array or single value
  let selectedItems = [];
  if (Array.isArray(req.body.selected_items)) {
    selectedItems = req.body.selected_items.map(id => String(id));
  } else if (req.body.selected_items) {
    selectedItems = [String(req.body.selected_items)];
  }

  logger.debug('POST /checkout - parsed selectedItems:', selectedItems);

  if (selectedItems.length === 0) {
    req.flash('error', 'Vui lòng chọn ít nhất một sản phẩm để thanh toán');
    return res.redirect('/cart');
  }

  // Store selected items in session for checkout
  req.session.selectedItems = selectedItems;
  logger.debug('POST /checkout - stored in session:', req.session.selectedItems);
  res.redirect('/checkout');
});

// POST /api/momo-callback - MoMo Callback (IPN) - Nhận kết quả từ MoMo (skip CSRF)
router.post('/api/momo-callback', async (req, res) => {
  const data = req.body;
  console.log("📩 MoMo Callback nhận được:", data);

  // Verify signature
  const rawSignature = `accessKey=${MOMO_ACCESS_KEY}&amount=${data.amount}&extraData=${data.extraData || ''}&message=${data.message}&orderId=${data.orderId}&orderInfo=${data.orderInfo}&orderType=${data.orderType}&partnerCode=${data.partnerCode}&payType=${data.payType}&requestId=${data.requestId}&responseTime=${data.responseTime}&resultCode=${data.resultCode}&transId=${data.transId}`;
  const signature = crypto.createHmac("sha256", MOMO_SECRET_KEY).update(rawSignature).digest("hex");

  if (signature !== data.signature) {
    console.log("❌ MoMo Callback: Chữ ký không hợp lệ!");
    console.log("🧩 Expected:", signature);
    console.log("🧩 Received:", data.signature);
    return res.status(400).send("Invalid signature");
  }

  // Process payment result
  if (data.resultCode === 0) {
    console.log(`✅ MoMo Giao dịch thành công: ${data.orderId} - ${data.amount} VND`);

    // Extract order ID from MoMo order ID (format: MOMO + orderId)
    const orderIdMatch = data.orderId.replace(MOMO_PARTNER_CODE, '');
    const orderId = parseInt(orderIdMatch);

    console.log('🔍 Processing MoMo callback:', {
      momoOrderId: data.orderId,
      extractedOrderId: orderId,
      resultCode: data.resultCode,
      amount: data.amount
    });

    if (!isNaN(orderId) && orderId > 0) {
      try {
        // Update order status to 'paid' and deduct stock
        // Use PostgreSQL instead of SQLite
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
        const order = orderResult.rows[0];

        console.log('🔍 Found order:', {
          orderId,
          orderExists: !!order,
          currentStatus: order?.status,
          userId: order?.user_id
        });

        // Only update if order is still pending (avoid duplicate updates)
        // Changed: accept both 'pending' and 'processing' status
        if (order && (order.status === 'pending' || order.status === 'processing')) {
          // Use transaction to ensure atomicity and prevent race conditions
          const client = await pool.connect();
          try {
            await client.query('BEGIN');

            // Lock the order row to prevent concurrent updates
            const lockResult = await client.query(
              'SELECT * FROM orders WHERE id = $1 FOR UPDATE',
              [orderId]
            );
            const lockedOrder = lockResult.rows[0];

            // Double-check status after locking (might have been updated by another process)
            // Changed: accept both 'pending' and 'processing' status
            if (lockedOrder && (lockedOrder.status === 'pending' || lockedOrder.status === 'processing')) {
              // Get order_item_ids for this order
              const orderItemIdsResult = await client.query(
                'SELECT id, product_id, quantity FROM order_items WHERE order_id = $1',
                [orderId]
              );
              const orderItemIds = orderItemIdsResult.rows;

              for (const orderItem of orderItemIds) {
                // Deduct stock
                await client.query(
                  'UPDATE products SET stock = stock - $1 WHERE id = $2',
                  [orderItem.quantity, orderItem.product_id]
                );

                // LƯU STOCK UPDATE VÀO FILE
                const productData = dataManager.findById('products', orderItem.product_id);
                if (productData) {
                  dataManager.updateItem('products', orderItem.product_id, {
                    stock: Math.max(0, (productData.stock || 0) - orderItem.quantity),
                    updated_at: new Date().toISOString()
                  });
                }

                // Get available product keys from product_keys table (only non-deleted keys)
                const availableKeysResult = await client.query(
                  'SELECT id, key_value FROM product_keys WHERE product_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC LIMIT $2',
                  [orderItem.product_id, orderItem.quantity]
                );
                const availableKeys = availableKeysResult.rows || [];

                // If product has enough keys, assign them to order_keys and soft delete from product_keys
                if (availableKeys.length > 0) {
                  for (let i = 0; i < availableKeys.length; i++) {
                    const productKey = availableKeys[i];
                    
                    // Insert into order_keys
                    const keyInsertResult = await client.query(
                      'INSERT INTO order_keys (order_item_id, key_value) VALUES ($1, $2) RETURNING id',
                      [orderItem.id, productKey.key_value]
                    );
                    const keyId = keyInsertResult.rows[0]?.id;

                    // Soft delete from product_keys by setting deleted_at
                    await client.query(
                      'UPDATE product_keys SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1',
                      [productKey.id]
                    );

                    // LƯU ORDER_KEY VÀO FILE TRONG DATA/
                    if (keyId) {
                      dataManager.addItem('order_keys', {
                        id: keyId,
                        order_item_id: orderItem.id,
                        key_value: productKey.key_value,
                        created_at: new Date().toISOString()
                      });
                    }
                  }
                  console.log(`🔑 Assigned ${availableKeys.length} key(s) for order_item #${orderItem.id}, product #${orderItem.product_id}`);
                  
                  if (availableKeys.length < orderItem.quantity) {
                    console.warn(`⚠️ Product #${orderItem.product_id} has only ${availableKeys.length} available keys but order needs ${orderItem.quantity}`);
                  }
                } else {
                  console.warn(`⚠️ Product #${orderItem.product_id} has no available keys`);
                }
              }

              // Update order status to 'paid' (removed 'processing', only 'paid' for success)
              const updateResult = await client.query(
                'UPDATE orders SET status = $1, payment_method = $2, payment_trans_id = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
                ['paid', 'momo', data.transId, orderId]
              );

              // LƯU VÀO FILE TRONG DATA/
              dataManager.updateItem('orders', orderId, {
                status: 'paid',
                payment_method: 'momo',
                payment_trans_id: data.transId,
                updated_at: new Date().toISOString()
              });

              await client.query('COMMIT');

              console.log(`✅ Đã cập nhật order #${orderId}:`, {
                orderId,
                status: 'paid',
                rowCount: updateResult.rowCount,
                payment_method: 'momo',
                payment_trans_id: data.transId
              });

              // Verify the update
              const verifyResult = await client.query('SELECT * FROM orders WHERE id = $1', [orderId]);
              const verifiedOrder = verifyResult.rows[0];
              console.log(`🔍 Verified order #${orderId}:`, {
                id: verifiedOrder?.id,
                status: verifiedOrder?.status,
                user_id: verifiedOrder?.user_id,
                payment_method: verifiedOrder?.payment_method
              });
            } else {
              await client.query('ROLLBACK');
              console.log(`⚠️ Order #${orderId} đã được xử lý bởi process khác (status: ${lockedOrder?.status})`);
            }
          } catch (updateErr) {
            await client.query('ROLLBACK');
            console.error(`❌ Lỗi trong transaction cập nhật order #${orderId}:`, updateErr);
            throw updateErr;
          } finally {
            client.release();
          }
        } else if (order && order.status !== 'pending' && order.status !== 'processing') {
          console.log(`⚠️ Order #${orderId} đã được xử lý trước đó (status: ${order.status})`);
        }
      } catch (err) {
        console.error(`❌ Lỗi cập nhật order #${orderId}:`, err);
      }
    } else {
      // Try to parse from extraData
      try {
        const extraData = JSON.parse(data.extraData || '{}');
        if (extraData.orderId) {
          const orderId = extraData.orderId;
          // Use PostgreSQL instead of SQLite
          const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [orderId]);
          const order = orderResult.rows[0];
          // Changed: accept both 'pending' and 'processing' status
          if (order && (order.status === 'pending' || order.status === 'processing')) {
            const client = await pool.connect();
            try {
              await client.query('BEGIN');

              // Lock the order row
              const lockResult = await client.query(
                'SELECT * FROM orders WHERE id = $1 FOR UPDATE',
                [orderId]
              );
              const lockedOrder = lockResult.rows[0];

              // Changed: accept both 'pending' and 'processing' status
              if (lockedOrder && (lockedOrder.status === 'pending' || lockedOrder.status === 'processing')) {
                // Get order_item_ids for this order
                const orderItemIdsResult = await client.query(
                  'SELECT id, product_id, quantity FROM order_items WHERE order_id = $1',
                  [orderId]
                );
                const orderItemIds = orderItemIdsResult.rows;

                for (const orderItem of orderItemIds) {
                  // Deduct stock
                  await client.query(
                    'UPDATE products SET stock = stock - $1 WHERE id = $2',
                    [orderItem.quantity, orderItem.product_id]
                  );

                  // LƯU STOCK UPDATE VÀO FILE
                  const productData = dataManager.findById('products', orderItem.product_id);
                  if (productData) {
                    dataManager.updateItem('products', orderItem.product_id, {
                      stock: Math.max(0, (productData.stock || 0) - orderItem.quantity),
                      updated_at: new Date().toISOString()
                    });
                  }

                  // Get available keys from product_keys (non-deleted) and assign them
                  const availableKeysResult2 = await client.query(
                    'SELECT id, key_value FROM product_keys WHERE product_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC LIMIT $2',
                    [orderItem.product_id, orderItem.quantity]
                  );
                  const availableKeys2 = availableKeysResult2.rows || [];

                  if (availableKeys2.length > 0) {
                    for (const pk of availableKeys2) {
                      const keyInsertResult = await client.query(
                        'INSERT INTO order_keys (order_item_id, key_value) VALUES ($1, $2) RETURNING id',
                        [orderItem.id, pk.key_value]
                      );
                      const keyId = keyInsertResult.rows[0]?.id;

                      // Soft delete assigned product key
                      await client.query('UPDATE product_keys SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1', [pk.id]);

                      // LƯU ORDER_KEY VÀO FILE TRONG DATA/
                      if (keyId) {
                        dataManager.addItem('order_keys', {
                          id: keyId,
                          order_item_id: orderItem.id,
                          key_value: pk.key_value,
                          created_at: new Date().toISOString()
                        });
                      }
                    }
                    console.log(`🔑 Assigned ${availableKeys2.length} key(s) for order_item #${orderItem.id}, product #${orderItem.product_id}`);
                    if (availableKeys2.length < orderItem.quantity) {
                      console.warn(`⚠️ Product #${orderItem.product_id} has only ${availableKeys2.length} available keys but order needs ${orderItem.quantity}`);
                    }
                  } else {
                    console.warn(`⚠️ Product #${orderItem.product_id} has no available keys`);
                  }
                }

                await client.query(
                  'UPDATE orders SET status = $1, payment_method = $2, payment_trans_id = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
                  ['paid', 'momo', data.transId, orderId]
                );

                // LƯU VÀO FILE TRONG DATA/
                dataManager.updateItem('orders', orderId, {
                  status: 'paid',
                  payment_method: 'momo',
                  payment_trans_id: data.transId,
                  updated_at: new Date().toISOString()
                });

                await client.query('COMMIT');
                console.log(`✅ Đã cập nhật order #${orderId} từ extraData`);
              } else {
                await client.query('ROLLBACK');
                console.log(`⚠️ Order #${orderId} đã được xử lý (status: ${lockedOrder?.status})`);
              }
            } catch (updateErr) {
              await client.query('ROLLBACK');
              console.error(`❌ Lỗi cập nhật order #${orderId} từ extraData:`, updateErr);
            } finally {
              client.release();
            }
          } else if (order && order.status !== 'pending' && order.status !== 'processing') {
            console.log(`⚠️ Order #${orderId} đã được xử lý trước đó (status: ${order.status})`);
          }
        }
      } catch (e) {
        console.log(`⚠️ Không tìm thấy order ID từ MoMo callback: ${data.orderId}`);
      }
    }
  } else {
    console.log(`❌ MoMo Giao dịch thất bại: ${data.orderId} - ${data.message}`);

    // Update order status to 'failed' if found
    const orderIdMatch = data.orderId.replace(MOMO_PARTNER_CODE, '');
    const orderId = parseInt(orderIdMatch);
    if (!isNaN(orderId) && orderId > 0) {
      try {
        await pool.query(
          'UPDATE orders SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
          ['failed', orderId]
        );

        // LƯU VÀO FILE TRONG DATA/
        dataManager.updateItem('orders', orderId, {
          status: 'failed',
          updated_at: new Date().toISOString()
        });
      } catch (err) {
        console.error(`❌ Lỗi cập nhật order #${orderId}:`, err);
      }
    }
  }

  res.status(204).end();
});

// GET /checkout/momo-success - MoMo Success Redirect Page
router.get('/checkout/momo-success', requireAuth, async (req, res) => {
  const { orderId, resultCode, message, transId } = req.query;

  // Clean up session
  const pendingOrderId = req.session.pendingOrderId;
  const pendingOrderItems = req.session.pendingOrderItems || [];
  delete req.session.pendingOrderId;
  delete req.session.pendingOrderItems;
  delete req.session.selectedItems;

  if (resultCode === '0') {
    // Extract order ID from MoMo order ID (format: MOMO + orderId)
    const extractedOrderId = pendingOrderId || (orderId ? parseInt(orderId.replace(MOMO_PARTNER_CODE, '')) : null);

    // Update order status if still pending (fallback in case callback hasn't processed yet)
    if (extractedOrderId && !isNaN(extractedOrderId) && extractedOrderId > 0) {
      try {
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [extractedOrderId]);
        const order = orderResult.rows[0];

        if (order && (order.status === 'pending' || order.status === 'processing')) {
          console.log(`🔄 Updating order #${extractedOrderId} status from momo-success route (callback may not have processed yet)`);

          const client = await pool.connect();
          try {
            await client.query('BEGIN');

            // Lock the order row to prevent concurrent updates
            const lockResult = await client.query(
              'SELECT * FROM orders WHERE id = $1 FOR UPDATE',
              [extractedOrderId]
            );
            const lockedOrder = lockResult.rows[0];

            // Double-check status after locking
            if (lockedOrder && (lockedOrder.status === 'pending' || lockedOrder.status === 'processing')) {
              // Get order_item_ids for this order
              const orderItemIdsResult = await client.query(
                'SELECT id, product_id, quantity FROM order_items WHERE order_id = $1',
                [extractedOrderId]
              );
              const orderItemIds = orderItemIdsResult.rows;

              for (const orderItem of orderItemIds) {
                // Deduct stock
                await client.query(
                  'UPDATE products SET stock = stock - $1 WHERE id = $2',
                  [orderItem.quantity, orderItem.product_id]
                );

                // LƯU STOCK UPDATE VÀO FILE
                const productData = dataManager.findById('products', orderItem.product_id);
                if (productData) {
                  dataManager.updateItem('products', orderItem.product_id, {
                    stock: Math.max(0, (productData.stock || 0) - orderItem.quantity),
                    updated_at: new Date().toISOString()
                  });
                }

                // Get available keys from product_keys (non-deleted) and assign them
                const availableKeysResult = await client.query(
                  'SELECT id, key_value FROM product_keys WHERE product_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC LIMIT $2',
                  [orderItem.product_id, orderItem.quantity]
                );
                const availableKeys = availableKeysResult.rows || [];

                if (availableKeys.length > 0) {
                  for (const pk of availableKeys) {
                    const keyInsertResult = await client.query(
                      'INSERT INTO order_keys (order_item_id, key_value) VALUES ($1, $2) RETURNING id',
                      [orderItem.id, pk.key_value]
                    );
                    const keyId = keyInsertResult.rows[0]?.id;

                    // Soft delete assigned product key
                    await client.query('UPDATE product_keys SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1', [pk.id]);

                    // Save to data files
                    if (keyId) {
                      dataManager.addItem('order_keys', {
                        id: keyId,
                        order_item_id: orderItem.id,
                        key_value: pk.key_value,
                        created_at: new Date().toISOString()
                      });
                    }
                  }
                  console.log(`🔑 Assigned ${availableKeys.length} key(s) for order_item #${orderItem.id}, product #${orderItem.product_id}`);
                  if (availableKeys.length < orderItem.quantity) {
                    console.warn(`⚠️ Product #${orderItem.product_id} has only ${availableKeys.length} available keys but order needs ${orderItem.quantity}`);
                  }
                } else {
                  console.warn(`⚠️ Product #${orderItem.product_id} has no available keys`);
                }
              }

              // Update order status to 'paid'
              await client.query(
                'UPDATE orders SET status = $1, payment_method = $2, payment_trans_id = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
                ['paid', 'momo', transId || null, extractedOrderId]
              );

              // LƯU VÀO FILE TRONG DATA/
              dataManager.updateItem('orders', extractedOrderId, {
                status: 'paid',
                payment_method: 'momo',
                payment_trans_id: transId || null,
                updated_at: new Date().toISOString()
              });

              await client.query('COMMIT');
              console.log(`✅ Đã cập nhật order #${extractedOrderId} từ momo-success route`);
            } else {
              await client.query('ROLLBACK');
              console.log(`⚠️ Order #${extractedOrderId} đã được xử lý bởi callback (status: ${lockedOrder?.status})`);
            }
          } catch (updateErr) {
            await client.query('ROLLBACK');
            console.error(`❌ Lỗi cập nhật order #${extractedOrderId} từ momo-success:`, updateErr);
            // Don't fail the redirect, just log the error
          } finally {
            client.release();
          }
        } else if (order && order.status === 'paid') {
          console.log(`✅ Order #${extractedOrderId} đã được xử lý (status: paid)`);
        }
      } catch (err) {
        console.error(`❌ Lỗi kiểm tra order #${extractedOrderId}:`, err);
        // Don't fail the redirect, just log the error
      }
    }

    // Remove purchased items from cart
    const cart = await getCart(req);
    pendingOrderItems.forEach(productId => {
      const key = String(productId);
      if (cart.items[key]) {
        cart.totalQty -= cart.items[key].qty;
        cart.totalCents -= cart.items[key].qty * cart.items[key].product.price_cents;
        delete cart.items[key];
      }
    });
    req.session.cart = cart; // Update session cart
    req.session.touch();

    // Save cart to database after removing purchased items
    if (req.session.user && req.session.user.id) {
      await saveCartToDatabase(req.session.user.id, cart);
    }

    const displayOrderId = extractedOrderId || 'N/A';
    // Redirect to keys page after successful payment
    res.redirect(`/orders/${displayOrderId}/keys`);
  } else {
    // Delete pending order if payment failed
    if (pendingOrderId) {
      try {
        const stmt1 = db.prepare('DELETE FROM order_items WHERE order_id = ?');
        await stmt1.run(pendingOrderId);
        const stmt2 = db.prepare('DELETE FROM orders WHERE id = ?');
        await stmt2.run(pendingOrderId);
      } catch (err) {
        console.error('Error deleting failed order:', err);
      }
    }
    req.flash('error', `Thanh toán MoMo thất bại: ${message || 'Lỗi không xác định'}`);
    res.redirect('/checkout');
  }
});

// POST /checkout/momo - Create order and initiate MoMo payment
router.post('/checkout/momo', requireAuth, async (req, res) => {
  // Get selected items from session
  const selectedItems = req.session.selectedItems || [];

  if (selectedItems.length === 0) {
    return res.status(400).json({ success: false, message: 'Không có sản phẩm nào được chọn' });
  }

  // Build itemsToProcess from selectedItems (can be from cart or buy_now)
  let itemsToProcess = {};
  let totalCents = 0;

  // Try to get from cart first
  const cart = await getCart(req);
  let hasItemsInCart = false;

  if (selectedItems.length > 0) {
    // Normalize selected items from cart: ensure price snapshots exist and reflect discounts
    const pStmt = db.prepare('SELECT price_cents, discount_percent FROM products WHERE id=?');
    for (const productId of selectedItems) {
      const key = String(productId);
      if (cart.items && cart.items[key]) {
        // ensure snapshot has original_price_cents and effective price
        const entry = cart.items[key];
        if (entry && entry.product) {
          if (!entry.product.original_price_cents) {
            try {
              const fresh = await pStmt.get(entry.product.id);
              const dbPrice = fresh ? (fresh.price_cents || 0) : (entry.product.price_cents || 0);
              const discount = fresh ? Number(fresh.discount_percent || 0) : Number(entry.product.discount_percent || 0);
              const effective = Math.round(dbPrice * (100 - discount) / 100);
              entry.product.price_cents = effective;
              entry.product.original_price_cents = dbPrice;
              entry.product.discount_percent = discount;
              // persist back to session
              if (req.session && req.session.cart && req.session.cart.items && req.session.cart.items[key]) {
                req.session.cart.items[key] = entry;
                req.session.touch && req.session.touch();
              }
            } catch (err) {
              console.error('Error normalizing cart item for checkout/momo:', err);
            }
          }
          itemsToProcess[key] = entry;
          totalCents += (entry.qty || 0) * (entry.product.price_cents || 0);
          hasItemsInCart = true;
        }
      }
    }
  }

  // If not in cart (buy_now case), fetch product directly from database
  if (!hasItemsInCart && selectedItems.length > 0) {
    const stmt = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
    for (const productId of selectedItems) {
      const product = await stmt.get(productId);
      if (product && (product.stock ?? 0) > 0) {
        const key = String(productId);
        // apply product-level discount for buy-now flow so totals match checkout page
        const dbPrice = product.price_cents || 0;
        const discountPercent = Number(product.discount_percent || 0);
        const effectivePrice = Math.round(dbPrice * (100 - discountPercent) / 100);

        itemsToProcess[key] = {
          product: {
            id: product.id,
            title: product.title,
            slug: product.slug,
            image: product.image,
            price_cents: effectivePrice,
            original_price_cents: dbPrice,
            discount_percent: discountPercent,
            stock: product.stock
          },
          qty: 1
        };
        totalCents += effectivePrice;
      }
    }
  }

  if (Object.keys(itemsToProcess).length === 0) {
    return res.status(400).json({ success: false, message: 'Không có sản phẩm nào được chọn hoặc sản phẩm đã hết hàng' });
  }

  // Verify stock
  const stockIssues = [];
  const stmt1 = db.prepare('SELECT stock, title FROM products WHERE id=?');
  for (const entry of Object.values(itemsToProcess)) {
    if (!entry || !entry.product) {
      stockIssues.push('Sản phẩm không hợp lệ');
      continue;
    }
    const fresh = await stmt1.get(entry.product.id);
    if (!fresh) {
      stockIssues.push(`Sản phẩm "${entry.product.title || 'Unknown'}" không tồn tại`);
      continue;
    }
    if (entry.qty > (fresh.stock ?? 0)) {
      stockIssues.push(`Không đủ tồn kho cho: ${fresh.title}`);
    }
  }

  if (stockIssues.length > 0) {
    return res.status(400).json({ success: false, message: stockIssues.join('; ') });
  }

  try {
    const userId = getUserId(req);
    console.log('🛒 Creating order for user:', userId, 'Total (cents):', totalCents, 'Items:', Object.keys(itemsToProcess).length);
    // Apply VAT (percent) to totalCents to compute finalTotal
    const vatPercentStr = await getSetting('vat_percent', '10');
    const vatPercent = Math.max(0, Math.min(100, parseInt(String(vatPercentStr || '0'), 10) || 0));
    const vatCents = Math.round(totalCents * vatPercent / 100);
    const finalTotalCents = totalCents + vatCents;
    // Debug: log cart summary
    try { console.log('🧾 Session cart totals:', req.session?.cart?.totalCents, 'original:', req.session?.cart?.originalTotalCents, 'discount:', req.session?.cart?.discountCents); } catch (e) { }

    // Create order with pending status
    // Use direct pool.query for RETURNING id to ensure we get the ID correctly
    // NOTE: we compute VAT for totals but do not store vat_percent/vat_cents in the DB schema
    const orderQuery = await pool.query(
      'INSERT INTO orders (user_id, total_cents, status, payment_method) VALUES ($1, $2, $3, $4) RETURNING id',
      [userId, finalTotalCents, 'pending', 'momo']
    );
    const orderId = orderQuery.rows[0]?.id;

    console.log('📝 Order created:', {
      orderId,
      userId,
      totalCents,
      status: 'pending',
      payment_method: 'momo',
      rows: orderQuery.rows
    });

    if (!orderId) {
      console.error('❌ Failed to create order - orderId is null');
      console.error('❌ Query result:', orderQuery);
      throw new Error('Không thể tạo đơn hàng');
    }

    // LƯU ORDER VÀO FILE TRONG DATA/
    const newOrder = {
      id: orderId,
      user_id: userId,
      total_cents: finalTotalCents,
      vat_percent: vatPercent,
      vat_cents: vatCents,
      status: 'pending',
      payment_method: 'momo',
      payment_trans_id: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    dataManager.addItem('orders', newOrder);

    // Store order items (but don't deduct stock yet - wait for MoMo confirmation)
    const insertItem = db.prepare('INSERT INTO order_items (order_id, product_id, quantity, price_cents) VALUES (?, ?, ?, ?)');
    let itemCount = 0;
    const orderItems = [];
    for (const entry of Object.values(itemsToProcess)) {
      if (entry && entry.product && entry.qty) {
        await insertItem.run(orderId, entry.product.id, entry.qty, entry.product.price_cents);

        // LƯU ORDER_ITEM VÀO FILE
        const orderItem = {
          id: null, // Will be set by auto-increment in file
          order_id: orderId,
          product_id: entry.product.id,
          quantity: entry.qty,
          price_cents: entry.product.price_cents
        };
        const savedItem = dataManager.addItem('order_items', orderItem);
        orderItems.push(savedItem);

        itemCount++;
        console.log(`  📦 Added item: product_id=${entry.product.id}, quantity=${entry.qty}`);
      }
    }
    console.log(`✅ Order #${orderId} created with ${itemCount} items`);

    // Store order ID in session for MoMo callback
    req.session.pendingOrderId = orderId;
    req.session.pendingOrderItems = selectedItems;

    // Create MoMo payment request
    // MoMo API requires amount in VND, but we store in cents, so convert
    const amountVND = Math.round(finalTotalCents / 100);
    const momoOrderId = MOMO_PARTNER_CODE + orderId;
    const requestId = momoOrderId;
    const orderInfo = `Thanh toán đơn hàng SafeKeyS #${orderId}`;
    const extraData = JSON.stringify({ orderId });
    const autoCapture = true;
    const expiredAt = Date.now() + 5 * 60 * 1000;

    const baseUrl = getBaseUrl(req);
    const redirectUrl = `${baseUrl}/checkout/momo-success`;
    const ipnUrl = `${baseUrl}/api/momo-callback`;

    const rawSignature = `accessKey=${MOMO_ACCESS_KEY}&amount=${amountVND}&extraData=${extraData}&ipnUrl=${ipnUrl}&orderId=${momoOrderId}&orderInfo=${orderInfo}&partnerCode=${MOMO_PARTNER_CODE}&redirectUrl=${redirectUrl}&requestId=${requestId}&requestType=${MOMO_REQUEST_TYPE}`;
    const signature = crypto.createHmac("sha256", MOMO_SECRET_KEY).update(rawSignature).digest("hex");

    const body = JSON.stringify({
      partnerCode: MOMO_PARTNER_CODE,
      partnerName: "SafeKeyS",
      storeId: "SafeKeySStore",
      requestId,
      amount: amountVND,
      orderId: momoOrderId,
      orderInfo,
      redirectUrl,
      ipnUrl,
      lang: MOMO_LANG,
      requestType: MOMO_REQUEST_TYPE,
      autoCapture,
      extraData,
      expiredAt,
      signature,
    });

    const options = {
      hostname: "test-payment.momo.vn",
      port: 443,
      path: "/v2/gateway/api/create",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const momoReq = https.request(options, (momoRes) => {
      let data = "";
      momoRes.on("data", chunk => (data += chunk));
      momoRes.on("end", async () => {
        try {
          const result = JSON.parse(data);
          console.log("📤 MoMo Create Response:", result);

          if (result.resultCode === 0 && result.payUrl) {
            res.json({
              success: true,
              payUrl: result.payUrl,
              orderId: orderId,
              momoOrderId: momoOrderId
            });
          } else {
            // Delete order if MoMo creation failed
            try {
              await db.prepare('DELETE FROM order_items WHERE order_id = ?').run(orderId);
              await db.prepare('DELETE FROM orders WHERE id = ?').run(orderId);
            } catch (deleteErr) {
              console.error('Error deleting order:', deleteErr);
            }
            res.status(400).json({
              success: false,
              message: result.message || 'Không thể tạo yêu cầu thanh toán MoMo'
            });
          }
        } catch (err) {
          console.error("❌ MoMo Parse Error:", err);
          try {
            await db.prepare('DELETE FROM order_items WHERE order_id = ?').run(orderId);
            await db.prepare('DELETE FROM orders WHERE id = ?').run(orderId);
          } catch (deleteErr) {
            console.error('Error deleting order:', deleteErr);
          }
          res.status(500).json({ success: false, message: "Lỗi xử lý phản hồi từ MoMo" });
        }
      });
    });

    momoReq.on("error", async (e) => {
      console.error("❌ MoMo Request Error:", e);
      try {
        await db.prepare('DELETE FROM order_items WHERE order_id = ?').run(orderId);
        await db.prepare('DELETE FROM orders WHERE id = ?').run(orderId);
      } catch (deleteErr) {
        console.error('Error deleting order:', deleteErr);
      }
      res.status(500).json({ success: false, message: e.message });
    });

    momoReq.write(body);
    momoReq.end();

  } catch (error) {
    console.error('MoMo order creation error:', error);
    res.status(500).json({ success: false, message: 'Có lỗi xảy ra khi tạo đơn hàng' });
  }
});

// POST /checkout/pay - Checkout step 2: pay (mock) with stock deduction
router.post('/checkout/pay', requireAuth, async (req, res) => {
  try {
    const cart = await getCart(req);
    if (!cart || cart.totalQty === 0 || !cart.items || Object.keys(cart.items).length === 0) {
      req.flash('error', 'Giỏ hàng trống');
      return res.redirect('/cart');
    }

    // Get selected items from session
    const selectedItems = req.session.selectedItems || [];
    let itemsToProcess = {};
    let totalCents = 0;

    if (selectedItems.length > 0) {
      // Only process selected items; if an item isn't in cart (buy_now), fetch from DB and apply discount
      const stmt = db.prepare('SELECT * FROM products WHERE id = ? AND active=1');
      for (const productId of selectedItems) {
        const key = String(productId);
        if (cart.items && cart.items[key]) {
          itemsToProcess[key] = cart.items[key];
          totalCents += cart.items[key].qty * cart.items[key].product.price_cents;
        } else {
          // buy_now fallback: fetch product and apply discount snapshot
          const product = await stmt.get(productId);
          if (product && (product.stock ?? 0) > 0) {
            const dbPrice = product.price_cents || 0;
            const discountPercent = Number(product.discount_percent || 0);
            const effectivePrice = Math.round(dbPrice * (100 - discountPercent) / 100);
            itemsToProcess[key] = {
              product: {
                id: product.id,
                title: product.title,
                slug: product.slug,
                image: product.image,
                price_cents: effectivePrice,
                original_price_cents: dbPrice,
                discount_percent: discountPercent,
                stock: product.stock
              },
              qty: 1
            };
            totalCents += effectivePrice;
          }
        }
      }
    } else {
      // If no selection, use all items (backward compatibility)
      itemsToProcess = cart.items;
      totalCents = cart.totalCents;
    }

    if (Object.keys(itemsToProcess).length === 0) {
      req.flash('error', 'Không có sản phẩm nào được chọn để thanh toán');
      return res.redirect('/checkout');
    }

    // Verify stock before deduct
    const stockIssues = [];
    const stmt = db.prepare('SELECT stock, title FROM products WHERE id=?');
    for (const entry of Object.values(itemsToProcess)) {
      if (!entry || !entry.product) {
        stockIssues.push('Sản phẩm không hợp lệ');
        continue;
      }

      const fresh = await stmt.get(entry.product.id);
      if (!fresh) {
        stockIssues.push(`Sản phẩm "${entry.product.title || 'Unknown'}" không tồn tại`);
        continue;
      }

      if (entry.qty > (fresh.stock ?? 0)) {
        stockIssues.push(`Không đủ tồn kho cho: ${fresh.title}`);
      }
    }

    if (stockIssues.length > 0) {
      req.flash('error', stockIssues.join('; '));
      return res.redirect('/checkout');
    }

    const orderId = await db.transaction(async (client) => {
      // compute VAT for mock payment orders
      const vatPercentStr = await getSetting('vat_percent', '10');
      const vatPercent = Math.max(0, Math.min(100, parseInt(String(vatPercentStr || '0'), 10) || 0));
      const vatCents = Math.round(totalCents * vatPercent / 100);
      const finalTotal = totalCents + vatCents;

      const orderRes = await client.query(
        'INSERT INTO orders (user_id, total_cents, status, payment_method) VALUES ($1, $2, $3, $4) RETURNING id',
        [getUserId(req), finalTotal, 'paid', 'mock']
      );
      const orderId = orderRes.rows[0]?.id;

      if (!orderId) {
        throw new Error('Không thể tạo đơn hàng');
      }

      // LƯU ORDER VÀO FILE TRONG DATA/
      const newOrder = {
        id: orderId,
        user_id: getUserId(req),
        total_cents: finalTotal,
        vat_percent: vatPercent,
        vat_cents: vatCents,
        status: 'paid',
        payment_method: 'mock',
        payment_trans_id: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      dataManager.addItem('orders', newOrder);

      const insertItem = db.prepare('INSERT INTO order_items (order_id, product_id, quantity, price_cents) VALUES (?, ?, ?, ?)');
      const decStock = db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?');

      for (const entry of Object.values(itemsToProcess)) {
        if (entry && entry.product && entry.qty) {
          // Insert order item and get order_item_id
          const itemResult = await pool.query(
            'INSERT INTO order_items (order_id, product_id, quantity, price_cents) VALUES ($1, $2, $3, $4) RETURNING id',
            [orderId, entry.product.id, entry.qty, entry.product.price_cents]
          );
          const orderItemId = itemResult.rows[0]?.id;

          // LƯU ORDER_ITEM VÀO FILE
          dataManager.addItem('order_items', {
            id: orderItemId,
            order_id: orderId,
            product_id: entry.product.id,
            quantity: entry.qty,
            price_cents: entry.product.price_cents
          });

          // Deduct stock
          await decStock.run(entry.qty, entry.product.id);

          // LƯU STOCK UPDATE VÀO FILE (update product)
          const productData = dataManager.findById('products', entry.product.id);
          if (productData) {
            dataManager.updateItem('products', entry.product.id, {
              stock: Math.max(0, (productData.stock || 0) - entry.qty),
              updated_at: new Date().toISOString()
            });
          }

          // Get available keys from product_keys and assign them to order
          if (orderItemId) {
            const pkRes = await client.query(
              'SELECT id, key_value FROM product_keys WHERE product_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC LIMIT $2',
              [entry.product.id, entry.qty]
            );
            const pks = pkRes.rows || [];
            if (pks.length > 0) {
              for (const pk of pks) {
                const keyInsert = await client.query(
                  'INSERT INTO order_keys (order_item_id, key_value) VALUES ($1, $2) RETURNING id',
                  [orderItemId, pk.key_value]
                );
                const newKeyId = keyInsert.rows[0]?.id || null;

                // Soft delete product key
                await client.query('UPDATE product_keys SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1', [pk.id]);

                // LƯU ORDER_KEY VÀO FILE
                dataManager.addItem('order_keys', {
                  id: newKeyId,
                  order_item_id: orderItemId,
                  key_value: pk.key_value,
                  created_at: new Date().toISOString()
                });
              }
              console.log(`🔑 Assigned ${pks.length} key(s) for order_item #${orderItemId}`);
              if (pks.length < entry.qty) console.warn(`⚠️ Product #${entry.product.id} has only ${pks.length} available keys but order needs ${entry.qty}`);
            } else {
              console.warn(`⚠️ Product #${entry.product.id} has no available keys`);
            }
          }
        }
      }

      return orderId;
    });

    // Remove purchased items from cart
    selectedItems.forEach(productId => {
      const key = String(productId);
      if (cart.items[key]) {
        cart.totalQty -= cart.items[key].qty;
        cart.totalCents -= cart.items[key].qty * cart.items[key].product.price_cents;
        delete cart.items[key];
      }
    });
    req.session.touch(); // Mark session as modified

    // Clean up session
    delete req.session.selectedItems;

    // Save session after cart update
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Error saving session after payment:', err);
          reject(err);
        } else {
          logger.debug('✅ Session saved after payment');
          resolve();
        }
      });
    });

    // Redirect to keys page after successful payment
    res.redirect(`/orders/${orderId}/keys`);
  } catch (error) {
    console.error('Payment error:', error);
    req.flash('error', 'Có lỗi xảy ra khi thanh toán. Vui lòng thử lại.');
    res.redirect('/checkout');
  }
});

export default router;
