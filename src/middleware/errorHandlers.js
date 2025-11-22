function generalErrorHandler(err, req, res, next) {
  console.error('Error:', err);

  if (err.code === 'EBADCSRFTOKEN') {
    req.flash('error', 'Phiên đăng nhập đã hết hạn. Vui lòng thử lại.');
    return res.redirect('back');
  }

  if (err.code && (err.code.startsWith('SQLITE_') || err.code.startsWith('23') || err.code.startsWith('42'))) {
    req.flash('error', 'Có lỗi xảy ra với cơ sở dữ liệu. Vui lòng thử lại sau.');
    return res.redirect('back');
  }

  res.status(err.status || 500).render('500', {
    title: 'Lỗi Server - SafeKeyS',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Đã xảy ra lỗi'
  });
}

function notFoundHandler(req, res) {
  console.log('❌ 404 - Route not found:', req.method, req.path);
  res.status(404).render('404', {
    title: '404 - Không tìm thấy - SafeKeyS'
  });
}

export { generalErrorHandler, notFoundHandler };



