export async function ensureReviewsTableExists(pool) {
    try {
        const existsRes = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'reviews'
      )
    `);
        if (!existsRes.rows[0].exists) {
            console.log('🔄 Tạo bảng reviews...');
            await pool.query(`
        CREATE TABLE reviews (
          id SERIAL PRIMARY KEY,
          product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
          user_id INTEGER REFERENCES users(id),
          author_name VARCHAR(255),
          rating INTEGER NOT NULL,
          title VARCHAR(255),
          body TEXT,
          images JSONB DEFAULT '[]',
          helpful_up INTEGER DEFAULT 0,
          helpful_down INTEGER DEFAULT 0,
          verified_purchase BOOLEAN DEFAULT false,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
            await pool.query('CREATE INDEX IF NOT EXISTS idx_reviews_product ON reviews(product_id)');
            // enforce one review per user per product (user_id NULL allowed for old data, but we will restrict new inserts)
            await pool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_reviews_product_user_unique ON reviews(product_id, user_id)');
            console.log('✅ Bảng reviews đã được tạo.');
        }
    } catch (err) {
        console.error('Error ensuring reviews table exists', err);
    }
}

export async function addReview(pool, review) {
    const {
        product_id, user_id = null, author_name = null, rating = 5, title = null, body = null, images = [], verified_purchase = false
    } = review;
    try {
        const res = await pool.query(
            `INSERT INTO reviews (product_id, user_id, author_name, rating, title, body, images, verified_purchase) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
            [product_id, user_id, author_name, rating, title, body, JSON.stringify(images), verified_purchase]
        );
        return res.rows[0];
    } catch (err) {
        // If unique constraint violation, throw a clear error
        if (err && err.code === '23505') {
            const e = new Error('User has already submitted a review for this product');
            e.code = 'USER_REVIEW_EXISTS';
            throw e;
        }
        throw err;
    }
}

export async function hasUserReviewed(pool, productId, userId) {
    if (!userId) return false;
    const res = await pool.query('SELECT 1 FROM reviews WHERE product_id = $1 AND user_id = $2 LIMIT 1', [productId, userId]);
    return res.rowCount > 0;
}

export async function getReviewsByProduct(pool, productId, { rating = null, limit = 50, offset = 0 } = {}) {
    const params = [productId];
    let sql = `SELECT * FROM reviews WHERE product_id = $1`;
    if (rating) {
        params.push(Number(rating));
        sql += ` AND rating = $${params.length}`;
    }
    sql += ` ORDER BY created_at DESC LIMIT ${Number(limit)} OFFSET ${Number(offset)}`;
    const res = await pool.query(sql, params);
    return res.rows;
}

export async function incrementHelpful(pool, reviewId, type = 'up') {
    if (!['up', 'down'].includes(type)) throw new Error('Invalid vote type');
    const col = type === 'up' ? 'helpful_up' : 'helpful_down';
    await pool.query(`UPDATE reviews SET ${col} = ${col} + 1 WHERE id = $1`, [reviewId]);
    const updated = await pool.query('SELECT helpful_up, helpful_down FROM reviews WHERE id = $1', [reviewId]);
    return updated.rows[0] || { helpful_up: 0, helpful_down: 0 };
}

export async function getReviewSummary(pool, productId) {
    const res = await pool.query(`
    SELECT COUNT(*)::int as count, COALESCE(ROUND(AVG(rating)::numeric,2),0)::numeric as avg
    FROM reviews WHERE product_id = $1
  `, [productId]);
    const count = res.rows[0] ? Number(res.rows[0].count) : 0;
    const avg = res.rows[0] ? Number(res.rows[0].avg) : 0;

    const breakdownRes = await pool.query(`
    SELECT rating, COUNT(*)::int as c FROM reviews WHERE product_id = $1 GROUP BY rating
  `, [productId]);
    const breakdown = {};
    for (const r of breakdownRes.rows) breakdown[r.rating] = r.c;

    return { count, avg, breakdown };
}
