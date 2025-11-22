import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';

const PgSession = connectPgSimple(session);

function createSessionMiddleware(pool) {
  const sessionStore = new PgSession({
    pool,
    tableName: 'sessions',
    createTableIfMissing: true
  });

  return session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'safekeys-secret-please-change',
    resave: true,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    },
    name: 'safekeys.sid'
  });
}

export { createSessionMiddleware };



