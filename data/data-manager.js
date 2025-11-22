import { pool } from '../src/config/database.js';

// In-memory cache to preserve synchronous API while persisting to PostgreSQL
const store = {
    users: [],
    products: [],
    orders: [],
    order_items: [],
    order_keys: [],
    categories: [],
    wishlist: [],
    carts: [],
    news: [],
    settings: {}
};

let initialized = false;

function runAsync(fn) {
    Promise.resolve().then(fn).catch(err => console.error('data-manager async error:', err));
}

async function initFromDB() {
    try {
        // Load arrays
        const tables = ['users', 'products', 'orders', 'order_items', 'order_keys', 'categories', 'wishlist', 'news'];
        for (const t of tables) {
            try {
                const res = await pool.query(`SELECT * FROM ${t} ORDER BY id`);
                store[t] = Array.isArray(res.rows) ? res.rows : [];
            } catch (e) {
                console.warn(`data-manager: failed to load table ${t}:`, e.message || e);
                store[t] = [];
            }
        }

        // Load carts (cart_data may be json)
        try {
            const res = await pool.query('SELECT * FROM carts ORDER BY id');
            store.carts = res.rows.map(r => ({
                id: r.id,
                user_id: r.user_id,
                cart_data: typeof r.cart_data === 'string' ? JSON.parse(r.cart_data) : r.cart_data,
                created_at: r.created_at,
                updated_at: r.updated_at
            }));
        } catch (e) {
            console.warn('data-manager: failed to load carts:', e.message || e);
            store.carts = [];
        }

        // Load settings as key/value object
        try {
            const res = await pool.query('SELECT key, value FROM settings');
            const obj = {};
            for (const row of res.rows) obj[row.key] = row.value;
            store.settings = obj;
        } catch (e) {
            console.warn('data-manager: failed to load settings:', e.message || e);
            store.settings = {};
        }

        initialized = true;
        console.info('data-manager: initialized from PostgreSQL');
    } catch (err) {
        console.error('data-manager init error:', err);
    }
}

// Start initialization in background
initFromDB();

// ----- Basic synchronous API backed by in-memory store -----
export function readData(table) {
    if (table === 'settings') return store.settings || {};
    return Array.isArray(store[table]) ? store[table] : [];
}

export function writeData(table, data) {
    if (table === 'settings') {
        store.settings = data || {};
        // Persist settings to DB asynchronously
        runAsync(async () => {
            try {
                // Upsert each setting
                const entries = Object.entries(store.settings || {});
                for (const [k, v] of entries) {
                    await pool.query(
                        'INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value',
                        [k, v]
                    );
                }
            } catch (e) {
                console.error('data-manager: writeData settings error:', e);
            }
        });
        return true;
    }

    // Replace full table contents in-memory
    store[table] = Array.isArray(data) ? data : [];
    // Persist to DB asynchronously: delete non-present rows and upsert present ones
    runAsync(async () => {
        try {
            // Start transaction
            const client = await pool.connect();
            try {
                await client.query('BEGIN');
                // Optionally clear table then insert all rows (simple approach)
                await client.query(`DELETE FROM ${table}`);
                for (const row of store[table]) {
                    const cols = Object.keys(row);
                    const vals = cols.map((_, i) => `$${i + 1}`);
                    const sql = `INSERT INTO ${table} (${cols.join(',')}) VALUES (${vals.join(',')})`;
                    await client.query(sql, cols.map(c => row[c]));
                }
                await client.query('COMMIT');
            } catch (e) {
                await client.query('ROLLBACK');
                console.error('data-manager: writeData transaction error for', table, e);
            } finally {
                client.release();
            }
        } catch (e) {
            console.error('data-manager: writeData error for', table, e);
        }
    });
    return true;
}

export function addItem(table, item) {
    if (table === 'settings') {
        // settings treated as object
        store.settings = store.settings || {};
        store.settings[item.key] = item.value;
        runAsync(async () => {
            try {
                await pool.query('INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value', [item.key, item.value]);
            } catch (e) {
                console.error('data-manager: addItem settings error:', e);
            }
        });
        return item;
    }

    const arr = store[table] || [];
    const maxId = arr.length > 0 ? Math.max(...arr.map(i => (i.id || 0))) : 0;
    if (!item.id || item.id === null) item.id = maxId + 1;
    const idx = arr.findIndex(i => i.id === item.id);
    if (idx !== -1) {
        arr[idx] = { ...arr[idx], ...item };
    } else {
        arr.push(item);
    }
    store[table] = arr;

    // Persist asynchronously (upsert)
    runAsync(async () => {
        try {
            const cols = Object.keys(item);
            const vals = cols.map((_, i) => `$${i + 1}`);
            const setClause = cols.filter(c => c !== 'id').map(c => `${c}=EXCLUDED.${c}`).join(',');
            const sql = `INSERT INTO ${table} (${cols.join(',')}) VALUES (${vals.join(',')}) ON CONFLICT (id) DO UPDATE SET ${setClause}`;
            await pool.query(sql, cols.map(c => item[c]));
        } catch (e) {
            console.error('data-manager: addItem upsert error for', table, e);
        }
    });

    return item;
}

export function updateItem(table, id, updates) {
    if (table === 'settings') {
        store.settings = store.settings || {};
        store.settings[id] = updates;
        runAsync(async () => {
            try {
                await pool.query('INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value', [id, updates]);
            } catch (e) {
                console.error('data-manager: updateItem settings error:', e);
            }
        });
        return store.settings[id];
    }

    const arr = store[table] || [];
    const index = arr.findIndex(item => item.id === id);
    if (index === -1) return null;
    arr[index] = { ...arr[index], ...updates };
    store[table] = arr;

    runAsync(async () => {
        try {
            const cols = Object.keys(updates);
            const setClause = cols.map((c, i) => `${c} = $${i + 1}`).join(', ');
            const sql = `UPDATE ${table} SET ${setClause} WHERE id = $${cols.length + 1}`;
            await pool.query(sql, [...cols.map(c => updates[c]), id]);
        } catch (e) {
            console.error('data-manager: updateItem error for', table, e);
        }
    });

    return arr[index];
}

export function deleteItem(table, id) {
    if (table === 'settings') {
        if (store.settings && store.settings[id] !== undefined) {
            delete store.settings[id];
            runAsync(async () => {
                try {
                    await pool.query('DELETE FROM settings WHERE key = $1', [id]);
                } catch (e) {
                    console.error('data-manager: deleteItem settings error:', e);
                }
            });
            return true;
        }
        return false;
    }

    const arr = store[table] || [];
    const index = arr.findIndex(item => item.id === id);
    if (index === -1) return false;
    arr.splice(index, 1);
    store[table] = arr;

    runAsync(async () => {
        try {
            await pool.query(`DELETE FROM ${table} WHERE id = $1`, [id]);
        } catch (e) {
            console.error('data-manager: deleteItem error for', table, e);
        }
    });

    return true;
}

export function findById(table, id) {
    if (table === 'settings') return store.settings[id] ?? null;
    const arr = store[table] || [];
    return arr.find(item => item.id === id) || null;
}

export function findWhere(table, condition) {
    const arr = store[table] || [];
    return arr.filter(item => {
        for (const [k, v] of Object.entries(condition)) {
            if (String(item[k]) !== String(v)) return false;
        }
        return true;
    });
}

export function getSetting(key, defaultValue = '') {
    return (store.settings && store.settings[key] !== undefined) ? store.settings[key] : defaultValue;
}

export function setSetting(key, value) {
    store.settings = store.settings || {};
    store.settings[key] = value;
    runAsync(async () => {
        try {
            await pool.query('INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value', [key, value]);
        } catch (e) {
            console.error('data-manager: setSetting error:', e);
        }
    });
}

// Sync from PostgreSQL to files (one-time migration)
export async function syncFromPostgreSQL(pool) {
    try {
        console.log('🔄 Đang đồng bộ dữ liệu từ PostgreSQL sang file...');

        // Sync users
        const usersResult = await pool.query('SELECT * FROM users ORDER BY id');
        writeData('users', usersResult.rows);
        console.log(`✅ Đã sync ${usersResult.rows.length} users`);

        // Sync products
        const productsResult = await pool.query('SELECT * FROM products ORDER BY id');
        writeData('products', productsResult.rows);
        console.log(`✅ Đã sync ${productsResult.rows.length} products`);

        // Sync orders
        const ordersResult = await pool.query('SELECT * FROM orders ORDER BY id');
        writeData('orders', ordersResult.rows);
        console.log(`✅ Đã sync ${ordersResult.rows.length} orders`);

        // Sync order_items
        const orderItemsResult = await pool.query('SELECT * FROM order_items ORDER BY id');
        writeData('order_items', orderItemsResult.rows);
        console.log(`✅ Đã sync ${orderItemsResult.rows.length} order_items`);

        // Sync order_keys
        const orderKeysResult = await pool.query('SELECT * FROM order_keys ORDER BY id');
        writeData('order_keys', orderKeysResult.rows);
        console.log(`✅ Đã sync ${orderKeysResult.rows.length} order_keys`);

        // Sync categories
        const categoriesResult = await pool.query('SELECT * FROM categories ORDER BY id');
        writeData('categories', categoriesResult.rows);
        console.log(`✅ Đã sync ${categoriesResult.rows.length} categories`);

        // Sync wishlist
        const wishlistResult = await pool.query('SELECT * FROM wishlist ORDER BY id');
        writeData('wishlist', wishlistResult.rows);
        console.log(`✅ Đã sync ${wishlistResult.rows.length} wishlist items`);

        // Sync carts
        const cartsResult = await pool.query('SELECT * FROM carts ORDER BY id');
        const carts = cartsResult.rows.map(row => ({
            id: row.id,
            user_id: row.user_id,
            cart_data: typeof row.cart_data === 'string' ? JSON.parse(row.cart_data) : row.cart_data,
            created_at: row.created_at,
            updated_at: row.updated_at
        }));
        writeData('carts', carts);
        console.log(`✅ Đã sync ${carts.length} carts`);

        // Sync news
        const newsResult = await pool.query('SELECT * FROM news ORDER BY id');
        writeData('news', newsResult.rows);
        console.log(`✅ Đã sync ${newsResult.rows.length} news`);

        // Sync settings
        const settingsResult = await pool.query('SELECT * FROM settings ORDER BY key');
        const settings = {};
        settingsResult.rows.forEach(row => {
            settings[row.key] = row.value;
        });
        writeData('settings', settings);
        console.log(`✅ Đã sync ${settingsResult.rows.length} settings`);

        console.log('✅ Hoàn thành đồng bộ dữ liệu!');
    } catch (error) {
        console.error('❌ Lỗi khi đồng bộ:', error);
        throw error;
    }
}

// Sync to PostgreSQL from files
export async function syncToPostgreSQL(pool) {
    try {
        console.log('🔄 Đang đồng bộ dữ liệu từ file sang PostgreSQL...');

        // Sync users
        const users = readData('users');
        for (const user of users) {
            await pool.query(
                `INSERT INTO users (id, email, password_hash, name, role, google_id, avatar, phone, address, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (id) DO UPDATE SET
         email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role,
         google_id = EXCLUDED.google_id, avatar = EXCLUDED.avatar,
         phone = EXCLUDED.phone, address = EXCLUDED.address,
         updated_at = EXCLUDED.updated_at`,
                [user.id, user.email, user.password_hash, user.name, user.role, user.google_id, user.avatar, user.phone, user.address, user.created_at, user.updated_at]
            );
        }
        console.log(`✅ Đã sync ${users.length} users`);

        // Sync other tables similarly...
        // (Implement for other tables as needed)

        console.log('✅ Hoàn thành đồng bộ dữ liệu!');
    } catch (error) {
        console.error('❌ Lỗi khi đồng bộ:', error);
        throw error;
    }
}


// Provide a grouped object for backward compatibility with code that
// imports `dataManager` and calls methods like `dataManager.addItem(...)`.
export const dataManager = {
    readData,
    writeData,
    addItem,
    updateItem,
    deleteItem,
    findById,
    findWhere,
    getSetting,
    setSetting,
    syncFromPostgreSQL,
    syncToPostgreSQL
};

export default dataManager;

