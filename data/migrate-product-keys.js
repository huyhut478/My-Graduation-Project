import { readData, addItem, updateItem } from './data-manager.js';
import { pool } from '../src/config/database.js';

async function migrate() {
    console.log('🔁 Starting migration: products.key_value -> product_keys');
    const products = readData('products') || [];
    let migrated = 0;
    for (const p of products) {
        if (p && p.key_value) {
            const createdAt = p.created_at || new Date().toISOString();
            const newPk = addItem('product_keys', {
                product_id: p.id,
                key_value: p.key_value,
                created_at: createdAt,
                deleted_at: null
            });

            // update file product to remove key_value
            try {
                updateItem('products', p.id, { key_value: null, updated_at: new Date().toISOString() });
            } catch (e) {
                console.warn(`Warning: failed to update product ${p.id} in files:`, e.message || e);
            }

            // attempt to insert into PostgreSQL
            try {
                await pool.query(
                    `INSERT INTO product_keys (id, product_id, key_value, created_at, deleted_at)
           VALUES ($1,$2,$3,$4,$5)
           ON CONFLICT (id) DO UPDATE SET
           product_id = EXCLUDED.product_id,
           key_value = EXCLUDED.key_value,
           created_at = EXCLUDED.created_at,
           deleted_at = EXCLUDED.deleted_at`,
                    [newPk.id, newPk.product_id, newPk.key_value, newPk.created_at, newPk.deleted_at]
                );
            } catch (e) {
                console.warn(`Warning: failed to insert product_key id=${newPk.id} into DB:`, e.message || e);
            }

            migrated++;
            console.log(`  ✅ Migrated product #${p.id} -> product_key id=${newPk.id}`);
        }
    }

    console.log(`🔚 Migration complete. Total migrated: ${migrated}`);
    console.log('Tip: run `npm run sync-to-postgresql` afterwards if you want to sync all files to DB.');
}

migrate().catch(err => {
    console.error('Migration failed:', err);
    process.exit(1);
});
