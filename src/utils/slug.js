import { pool } from '../config/database.js';

function slugify(input) {
  const base = (input || '').toString().trim().toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '') || 'bai-viet';
  return base;
}

async function generateUniqueSlug(baseSlug, excludeId) {
  let slug = slugify(baseSlug);
  const exists = async (s) => {
    let query = 'SELECT id FROM news WHERE slug = $1';
    const params = [s];
    if (excludeId) {
      query += ' AND id <> $2';
      params.push(excludeId);
    }
    const result = await pool.query(query, params);
    return result.rows.length > 0;
  };
  if (!(await exists(slug))) return slug;
  let i = 2;
  while (await exists(`${slug}-${i}`)) i++;
  return `${slug}-${i}`;
}

export { slugify, generateUniqueSlug };



