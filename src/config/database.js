import pkg from 'pg';
import { logger } from './logger.js';

const { Pool } = pkg;

const pgConfig = {
  host: process.env.PG_HOST || 'localhost',
  port: parseInt(process.env.PG_PORT || '5432'),
  database: process.env.PG_DATABASE || 'safekeys',
  user: process.env.PG_USER || 'postgres',
  password: process.env.PG_PASSWORD || '',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
};

logger.debug && logger.debug('📋 PostgreSQL Config:', {
  host: pgConfig.host,
  port: pgConfig.port,
  database: pgConfig.database,
  user: pgConfig.user,
  password: pgConfig.password ? '***' : 'KHÔNG CÓ'
});

export const pool = new Pool(pgConfig);

function convertSQL(sql) {
  let converted = sql
    .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'SERIAL PRIMARY KEY')
    .replace(/AUTOINCREMENT/g, 'SERIAL')
    .replace(/DATETIME/g, 'TIMESTAMP')
    .replace(/TEXT(?=\s|,|\))/g, 'VARCHAR(255)')
    .replace(/INSERT OR IGNORE/g, 'INSERT')
    .replace(/PRAGMA table_info\((\w+)\)/g, `SELECT column_name as name FROM information_schema.columns WHERE table_name = '$1'`);

  let paramIndex = 1;
  converted = converted.replace(/\?/g, () => `$${paramIndex++}`);

  return converted;
}

export const db = {
  async query(sql, params = []) {
    try {
      const convertedSQL = convertSQL(sql);
      const result = await pool.query(convertedSQL, params);
      return result;
    } catch (error) {
      console.error('Database query error:', error);
      console.error('SQL:', sql);
      throw error;
    }
  },
  prepare(sql) {
    const convertedSQL = convertSQL(sql);
    return {
      get: async (...params) => {
        const result = await pool.query(convertedSQL, params);
        return result.rows[0] || null;
      },
      all: async (...params) => {
        const result = await pool.query(convertedSQL, params);
        return result.rows;
      },
      run: async (...params) => {
        const result = await pool.query(convertedSQL, params);
        return {
          lastInsertRowid: result.rows[0]?.id || null,
          changes: result.rowCount || 0
        };
      }
    };
  },
  async exec(sql) {
    try {
      const convertedSQL = convertSQL(sql);
      await pool.query(convertedSQL);
    } catch (error) {
      console.error('Database exec error:', error);
      console.error('SQL:', sql);
      throw error;
    }
  },
  async transaction(callback) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
};
