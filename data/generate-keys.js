#!/usr/bin/env node

/**
 * Generate Product Keys Script
 * Tạo keys cho các sản phẩm dựa trên tồn kho
 * 
 * Usage: npm run generate-keys
 * Không ảnh hưởng đến ứng dụng chính
 */

import 'dotenv/config';
import pkg from 'pg';
const { Pool } = pkg;
import crypto from 'crypto';

const pool = new Pool({
    host: process.env.PG_HOST || 'localhost',
    port: parseInt(process.env.PG_PORT || '5432'),
    database: process.env.PG_DATABASE || 'safekeys',
    user: process.env.PG_USER || 'postgres',
    password: process.env.PG_PASSWORD || '',
});

/**
 * Generate một random key duy nhất
 * Format: XXXX-XXXX-XXXX-XXXX (16 ký tự hex)
 */
function generateUniqueKey() {
    return crypto.randomBytes(8).toString('hex').toUpperCase();
}

/**
 * Tạo key với format tùy chỉnh
 * Formats: 'FULL', 'SHORT', 'UUID'
 */
function generateKey(format = 'FULL') {
    switch (format.toUpperCase()) {
        case 'SHORT':
            // 8 ký tự: XXXXXXXX
            return crypto.randomBytes(4).toString('hex').toUpperCase();

        case 'UUID':
            // Format UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            return [
                crypto.randomBytes(4).toString('hex'),
                crypto.randomBytes(2).toString('hex'),
                crypto.randomBytes(2).toString('hex'),
                crypto.randomBytes(2).toString('hex'),
                crypto.randomBytes(6).toString('hex'),
            ].join('-').toUpperCase();

        case 'FULL':
        default:
            // Format mặc định: XXXX-XXXX-XXXX-XXXX
            return [
                crypto.randomBytes(2).toString('hex'),
                crypto.randomBytes(2).toString('hex'),
                crypto.randomBytes(2).toString('hex'),
                crypto.randomBytes(2).toString('hex'),
            ].join('-').toUpperCase();
    }
}

/**
 * Kiểm tra xem key đã tồn tại chưa
 */
async function keyExists(keyValue, client) {
    const result = await client.query(
        'SELECT id FROM product_keys WHERE key_value = $1 LIMIT 1',
        [keyValue]
    );
    return result.rows.length > 0;
}

/**
 * Generate keys cho 1 sản phẩm
 */
async function generateKeysForProduct(productId, requiredCount, format = 'FULL', client) {
    try {
        // Lấy thông tin sản phẩm
        const productResult = await client.query(
            'SELECT id, title, stock FROM products WHERE id = $1',
            [productId]
        );

        if (productResult.rows.length === 0) {
            console.warn(`⚠️  Sản phẩm #${productId} không tồn tại. Bỏ qua.`);
            return 0;
        }

        const product = productResult.rows[0];

        // Kiểm tra xem đã có bao nhiêu keys rồi
        const existingKeysResult = await client.query(
            'SELECT COUNT(*) as count FROM product_keys WHERE product_id = $1 AND deleted_at IS NULL',
            [productId]
        );
        const existingCount = parseInt(existingKeysResult.rows[0].count || 0);

        // Tính số keys cần tạo
        const keysToGenerate = Math.max(0, requiredCount - existingCount);

        if (keysToGenerate === 0) {
            console.log(`  ✓ Sản phẩm #${productId} (${product.title}): Đã đủ keys (${existingCount}/${requiredCount})`);
            return 0;
        }

        console.log(`  📝 Sản phẩm #${productId} (${product.title}): Tạo ${keysToGenerate} keys...`);

        let generatedCount = 0;
        const maxAttempts = keysToGenerate * 5; // Tránh vòng lặp vô hạn nếu trùng
        let attempts = 0;

        while (generatedCount < keysToGenerate && attempts < maxAttempts) {
            const keyValue = generateKey(format);

            // Kiểm tra trùng
            const exists = await keyExists(keyValue, client);
            if (!exists) {
                await client.query(
                    'INSERT INTO product_keys (product_id, key_value, created_at, deleted_at) VALUES ($1, $2, CURRENT_TIMESTAMP, NULL)',
                    [productId, keyValue]
                );
                generatedCount++;
            }
            attempts++;
        }

        console.log(`  ✅ Sản phẩm #${productId}: Tạo thành công ${generatedCount} keys`);
        return generatedCount;
    } catch (error) {
        console.error(`  ❌ Lỗi khi tạo keys cho sản phẩm #${productId}:`, error.message);
        return 0;
    }
}

/**
 * Main function - Tạo keys cho tất cả sản phẩm
 */
async function generateAllKeys(options = {}) {
    const {
        keyFormat = 'FULL',  // FULL, SHORT, UUID
        strategy = 'stock',  // 'stock' (bằng tồn kho) hoặc 'custom' (tùy chỉnh)
        customCount = 10,    // Số lượng keys nếu dùng strategy 'custom'
        productIds = null,   // Nếu null, tạo cho tất cả; nếu array, chỉ tạo cho những sản phẩm này
    } = options;

    console.log('🔑 Đang tạo Product Keys...\n');
    console.log(`⚙️  Cài đặt:`);
    console.log(`   Format: ${keyFormat}`);
    console.log(`   Strategy: ${strategy}`);
    if (strategy === 'custom') console.log(`   Custom Count: ${customCount}`);
    console.log(`   Scope: ${productIds ? `Sản phẩm #${productIds.join(', #')}` : 'Tất cả sản phẩm'}\n`);

    const client = await pool.connect();
    let totalGenerated = 0;

    try {
        await client.query('BEGIN');

        let query = 'SELECT id, stock, title FROM products WHERE active = 1 ORDER BY id';
        let queryParams = [];

        if (productIds && productIds.length > 0) {
            const placeholders = productIds.map((_, i) => `$${i + 1}`).join(',');
            query = `SELECT id, stock, title FROM products WHERE id IN (${placeholders}) AND active = 1 ORDER BY id`;
            queryParams = productIds;
        }

        const productsResult = await client.query(query, queryParams);
        const products = productsResult.rows;

        console.log(`📦 Tìm thấy ${products.length} sản phẩm\n`);

        for (const product of products) {
            let requiredCount;

            if (strategy === 'stock') {
                requiredCount = product.stock || 0;
            } else if (strategy === 'custom') {
                requiredCount = customCount;
            } else {
                requiredCount = product.stock || 0;
            }

            const generated = await generateKeysForProduct(product.id, requiredCount, keyFormat, client);
            totalGenerated += generated;
        }

        await client.query('COMMIT');

        console.log(`\n✅ Hoàn thành! Tạo tổng cộng ${totalGenerated} keys mới.`);
        return totalGenerated;
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('\n❌ Lỗi:', error.message);
        throw error;
    } finally {
        client.release();
    }
}

/**
 * Parse command line arguments
 */
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {
        keyFormat: 'FULL',
        strategy: 'stock',
        customCount: 10,
        productIds: null,
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg === '--format' && args[i + 1]) {
            options.keyFormat = args[i + 1].toUpperCase();
            i++;
        } else if (arg === '--strategy' && args[i + 1]) {
            options.strategy = args[i + 1].toLowerCase();
            i++;
        } else if (arg === '--count' && args[i + 1]) {
            options.customCount = parseInt(args[i + 1], 10);
            i++;
        } else if (arg === '--products' && args[i + 1]) {
            options.productIds = args[i + 1].split(',').map(id => parseInt(id.trim(), 10));
            i++;
        } else if (arg === '--help') {
            printHelp();
            process.exit(0);
        }
    }

    return options;
}

/**
 * In hướng dẫn
 */
function printHelp() {
    console.log(`
🔑 Generate Product Keys Script

Usage: npm run generate-keys [options]

Options:
  --format <FORMAT>       Format key: FULL (default), SHORT, UUID
  --strategy <STRATEGY>   Chiến lược: stock (default), custom
  --count <COUNT>         Số lượng keys nếu dùng strategy 'custom' (default: 10)
  --products <IDS>        Chỉ tạo cho sản phẩm cụ thể (VD: 1,2,3)
  --help                  Hiển thị hướng dẫn này

Examples:
  # Tạo keys bằng tồn kho (mặc định)
  npm run generate-keys

  # Tạo keys với format UUID
  npm run generate-keys --format UUID

  # Tạo 20 keys cho mỗi sản phẩm
  npm run generate-keys --strategy custom --count 20

  # Chỉ tạo keys cho sản phẩm #1, #2, #3
  npm run generate-keys --products 1,2,3

  # Kết hợp các tùy chọn
  npm run generate-keys --format SHORT --strategy custom --count 50 --products 5,10,15

Key Formats:
  FULL   - XXXX-XXXX-XXXX-XXXX (16 ký tự)
  SHORT  - XXXXXXXX (8 ký tự)
  UUID   - XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

Strategies:
  stock  - Tạo keys = tồn kho sản phẩm
  custom - Tạo keys = số lượng chỉ định
  `);
}

// Run
if (process.argv[2] === '--help') {
    printHelp();
    process.exit(0);
}

const options = parseArgs();

generateAllKeys(options)
    .then(() => {
        console.log('\n🎉 Script hoàn thành thành công!');
        process.exit(0);
    })
    .catch((error) => {
        console.error('\n💥 Script thất bại:', error);
        process.exit(1);
    })
    .finally(() => {
        pool.end();
    });
