const KEYS_MANAGEMENT_PASSWORD = process.env.KEYS_MANAGEMENT_PASSWORD || '141514';

function getUser(req) {
  return req.session?.user || req.user || null;
}

function getUserId(req) {
  const user = getUser(req);
  return user?.id || null;
}

function requireAuth(req, res, next) {
  if (!req.session) {
    req.flash('error', 'Phiên đăng nhập không hợp lệ. Vui lòng đăng nhập lại.');
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }

  const user = getUser(req);
  if (!user) {
    req.flash('error', 'Vui lòng đăng nhập để tiếp tục');
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }

  if (req.user && !req.session.user) {
    req.session.user = {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      avatar: req.user.avatar || null
    };
  }

  if (req.session && !req.session.regenerated) {
    req.session.regenerated = true;
  }

  next();
}

function requireAdmin(req, res, next) {
  const user = getUser(req);
  if (!user) {
    req.flash('error', 'Vui lòng đăng nhập');
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  if (user.role !== 'admin') {
    return res.status(403).render('403', {
      title: '403 - Truy cập bị từ chối - SafeKeyS'
    });
  }
  next();
}

function requireKeysPassword(req, res, next) {
  if (req.session.keysPasswordVerified) {
    return next();
  }

  let csrfToken = '';
  try {
    if (req.csrfToken && typeof req.csrfToken === 'function') {
      csrfToken = req.csrfToken();
    } else if (res.locals.csrfToken) {
      csrfToken = res.locals.csrfToken;
    }
  } catch {
    csrfToken = '';
  }
  const hasError = req.query.error === '1' || req.query.error === 'true';
  res.locals.layout = false;
  return res.render('admin/keys-password-standalone', {
    title: 'Xác thực mật khẩu - Quản lý Key',
    error: hasError,
    csrfToken: csrfToken
  }, (err, html) => {
    if (err) {
      console.error('Error rendering password form:', err);
      return res.status(500).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Lỗi</title><style>body{font-family:Arial;padding:40px;text-align:center;background:#0f172a;color:#e5e7eb;}</style></head><body><h1>Lỗi hiển thị form</h1><p>${err.message}</p><a href="/admin" style="color:#16a34a;">Quay lại Admin</a></body></html>`);
    }
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });
}

export { getUser, getUserId, requireAuth, requireAdmin, requireKeysPassword, KEYS_MANAGEMENT_PASSWORD };



