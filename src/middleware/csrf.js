import csrf from 'csurf';

function createCsrfMiddleware() {
  const csrfProtection = csrf({
    cookie: false,
    sessionKey: 'session',
    value: (req) => {
      return (
        req.body && req.body._csrf ||
        req.query && req.query._csrf ||
        req.headers['csrf-token'] ||
        req.headers['xsrf-token'] ||
        req.headers['x-csrf-token'] ||
        req.headers['x-xsrf-token']
      );
    }
  });

  return (req, res, next) => {
    const skipPaths = [
      '/api/',
      '/admin/settings/save',
      '/checkout/momo',
      '/profile',
      '/admin/products'
    ];

    const shouldSkip = skipPaths.some(path => req.path.startsWith(path));

    if (shouldSkip) {
      return next();
    }

    csrfProtection(req, res, (err) => {
      if (err) {
        if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
          console.warn('⚠️  CSRF error on safe method, ignoring', err.message);
          return next();
        }
        req.flash('error', 'Phiên làm việc đã hết hạn. Vui lòng thử lại.');
        return res.redirect('back');
      }
      next();
    });
  };
}

function csrfErrorHandler(err, req, res, next) {
  if (err.code === 'EBADCSRFTOKEN') {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }
    req.flash('error', 'Token bảo mật không hợp lệ. Vui lòng thử lại.');
    return res.redirect('back');
  }
  next(err);
}

export { createCsrfMiddleware, csrfErrorHandler };



