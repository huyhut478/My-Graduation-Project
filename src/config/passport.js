import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { db, pool } from './database.js';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback';

function configurePassport(passport) {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.warn('⚠️  Google OAuth credentials not set. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.');
    return;
  }

  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
  },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const stmt1 = db.prepare('SELECT * FROM users WHERE google_id = ?');
        let user = await stmt1.get(profile.id);

        if (user) {
          const stmt2 = db.prepare(`
          UPDATE users 
          SET name = ?, avatar = ?, email = ?, updated_at = CURRENT_TIMESTAMP 
          WHERE google_id = ?
        `);
          await stmt2.run(profile.displayName, profile.photos?.[0]?.value || null, profile.emails?.[0]?.value, profile.id);
          const stmt3 = db.prepare('SELECT * FROM users WHERE google_id = ?');
          user = await stmt3.get(profile.id);
          return done(null, user);
        }

        const stmt4 = db.prepare('SELECT * FROM users WHERE email = ?');
        user = await stmt4.get(profile.emails?.[0]?.value);

        if (user) {
          await pool.query(
            'UPDATE users SET google_id = $1, avatar = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
            [profile.id, profile.photos?.[0]?.value || null, user.id]
          );
          const stmt6 = db.prepare('SELECT * FROM users WHERE id = ?');
          user = await stmt6.get(user.id);
          return done(null, user);
        }

        const result = await pool.query(
          `INSERT INTO users (email, name, google_id, avatar, role)
           VALUES ($1, $2, $3, $4, 'customer')
           RETURNING id`,
          [
            profile.emails?.[0]?.value,
            profile.displayName,
            profile.id,
            profile.photos?.[0]?.value || null
          ]
        );
        const userId = result.rows[0]?.id;
        const stmt8 = db.prepare('SELECT * FROM users WHERE id = ?');
        user = await stmt8.get(userId);
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }));

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
      const user = await stmt.get(id);
      done(null, user || null);
    } catch (err) {
      done(err, null);
    }
  });
}

export { configurePassport, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL };



