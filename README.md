# SafeKeyS - Hệ thống bán Key phần mềm và Game

Hệ thống bán key phần mềm và game với đầy đủ tính năng quản lý, thanh toán MoMo, và quản lý dữ liệu.

## 🚀 Tính năng chính

- ✅ **Quản lý sản phẩm**: Thêm, sửa, xóa sản phẩm với danh mục
- ✅ **Quản lý đơn hàng**: Xem lịch sử đơn hàng, quản lý trạng thái
- ✅ **Thanh toán MoMo**: Tích hợp cổng thanh toán MoMo
- ✅ **Giỏ hàng**: Lưu giỏ hàng vào database, không mất khi đăng xuất
- ✅ **Quản lý người dùng**: Đăng ký, đăng nhập, hồ sơ cá nhân
- ✅ **Yêu thích**: Danh sách sản phẩm yêu thích
- ✅ **Tin tức**: Quản lý tin tức, bài viết
- ✅ **Admin Panel**: Dashboard quản lý toàn diện
- ✅ **Lưu trữ dữ liệu**: Dữ liệu được lưu vào PostgreSQL

## 📋 Yêu cầu hệ thống

- Node.js >= 18.x
- PostgreSQL >= 12.x
- npm hoặc yarn

## 🔧 Cài đặt

### 1. Clone repository

```bash
git clone <repository-url>
cd SafeKeyS
```

### 2. Cài đặt dependencies

```bash
npm install
```

### 3. Cấu hình môi trường

Tạo file `.env` trong thư mục gốc với các biến sau:

#### 📝 Ví dụ file `.env` đầy đủ

```env
# ============================================
# PostgreSQL Configuration
# ============================================
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=safekeys
PG_USER=postgres
PG_PASSWORD=your_database_password

# ============================================
# Server Configuration
# ============================================
PORT=3000
NODE_ENV=development

# ============================================
# Session & Security
# ============================================
SESSION_SECRET=your_session_secret_key_here_change_in_production

# ============================================
# MoMo Payment Configuration
# ============================================
MOMO_ACCESS_KEY=your_momo_access_key_here
MOMO_SECRET_KEY=your_momo_secret_key_here
MOMO_PARTNER_CODE=MOMO
MOMO_REQUEST_TYPE=captureWallet
MOMO_LANG=vi

# ============================================
# Google OAuth (Optional - để trống nếu không dùng)
# ============================================
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# ============================================
# SMTP Configuration for sending emails
# ============================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password_here

# ============================================
# OTP Configuration
# ============================================
OTP_EXPIRE_SECONDS=120
```

#### 📌 Chi tiết các biến môi trường

**PostgreSQL Configuration:**
| Biến | Mô tả | Ví dụ | Mặc định |
|------|-------|-------|---------|
| `PG_HOST` | Host của PostgreSQL server | `localhost` | `localhost` |
| `PG_PORT` | Port của PostgreSQL | `5432` | `5432` |
| `PG_DATABASE` | Tên database | `safekeys` | `safekeys` |
| `PG_USER` | Username PostgreSQL | `postgres` | `postgres` |
| `PG_PASSWORD` | Password PostgreSQL | `123456` | `123456` |

**Server Configuration:**
| Biến | Mô tả | Giá trị |
|------|-------|--------|
| `PORT` | Cổng chạy server | `3000` (hoặc cổng khác) |
| `NODE_ENV` | Môi trường chạy | `development` hoặc `production` |

**MoMo Payment:**
| Biến | Mô tả | Giá trị mặc định |
|------|-------|-----------------|
| `MOMO_ACCESS_KEY` | Access key MoMo | `F8BBA842ECF85` (test) |
| `MOMO_SECRET_KEY` | Secret key MoMo | `K951B6PE1waDMi640xX08PD3vg6EkVlz` (test) |
| `MOMO_PARTNER_CODE` | Mã đối tác MoMo | `MOMO` |
| `MOMO_REQUEST_TYPE` | Loại yêu cầu | `captureWallet` |
| `MOMO_LANG` | Ngôn ngữ | `vi` (tiếng Việt) |

**Google OAuth (Tùy chọn):**
- Để trống nếu không dùng Google login
- Lấy từ Google Cloud Console

**SMTP (Email):**
| Biến | Mô tả |
|------|-------|
| `SMTP_HOST` | Server SMTP (ví dụ: gmail) |
| `SMTP_PORT` | Port SMTP (gmail: 587) |
| `SMTP_SECURE` | Dùng TLS/SSL (false = TLS, true = SSL) |
| `SMTP_USER` | Email để gửi |
| `SMTP_PASS` | Mật khẩu hoặc App password |

#### ⚙️ Hướng dẫn cấu hình cho từng môi trường

**Development (localhost):**
```env
NODE_ENV=development
PORT=3000
PG_HOST=localhost
# Dùng test keys của MoMo
```

**Production (Server):**
```env
NODE_ENV=production
PORT=3000
PG_HOST=your_server_ip_or_domain
SESSION_SECRET=your-long-random-secret-key-here-change-this
# Dùng production keys từ MoMo
MOMO_ACCESS_KEY=your_production_access_key
MOMO_SECRET_KEY=your_production_secret_key
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```

#### 🔑 Cách lấy MoMo Production Keys:
1. Đăng ký tài khoản Merchant tại MoMo
2. Vào MoMo Developer Dashboard
3. Copy `ACCESS_KEY` và `SECRET_KEY` từ phần cài đặt
4. Cập nhật vào file `.env`

#### 📧 Cách lấy Gmail App Password:
1. Bật 2-factor authentication trên tài khoản Gmail
2. Vào https://myaccount.google.com/apppasswords
3. Chọn "Mail" và "Windows Computer" (hoặc tương tự)
4. Lấy mật khẩu 16 ký tự, cập nhật vào `SMTP_PASS`

### 4. Tạo database

```bash
npm run create-db
```

Hoặc tạo thủ công:

```sql
CREATE DATABASE safekeys;
```

Sau đó import schema từ `data/safekeys-database.sql` (nếu có).

### 5. Tạo bảng user_carts (cho tính năng lưu giỏ hàng)

```bash
npm run create-user-carts-table
```

### 6. Khởi động server

**Development mode (với nodemon):**
```bash
npm run dev
```

**Production mode:**
```bash
npm start
```

Server sẽ chạy tại: `http://localhost:3000`

## Thêm favicon (logo tab / icon trang)

Để thêm favicon cho trang, bạn có thể đặt file `favicon.ico` vào thư mục `public/img/icons` của dự án (đường dẫn sẽ là `public/img/icons/favicon.ico`).


## 📁 Cấu trúc dữ liệu

Dữ liệu được lưu trữ ở :

### 1. PostgreSQL Database
- Tất cả dữ liệu chính (users, products, orders, etc.)
- Session data (giỏ hàng, đăng nhập)
- User carts (giỏ hàng theo user_id)


## 🔄 Scripts có sẵn

### Quản lý database
```bash
# Tạo database và import schema
npm run create-db

# Tạo bảng user_carts (cho tính năng lưu giỏ hàng)
npm run create-user-carts-table
```


### Chạy server
```bash
# Development mode (tự động restart khi có thay đổi)
npm run dev

# Production mode
npm start
```

## 🎯 Tính năng chi tiết

### Giỏ hàng
- Giỏ hàng được lưu vào PostgreSQL session store
- Giỏ hàng được lưu vào database theo `user_id` khi logout
- Giỏ hàng được restore khi login lại
- Không mất giỏ hàng khi reload trang hoặc đăng xuất/đăng nhập

### Thanh toán
- **MoMo Payment**: Tích hợp cổng thanh toán MoMo
- **Mock Payment**: Thanh toán thử nghiệm (không cần tiền thật)
- Keys được lưu vào `order_keys` sau khi thanh toán thành công

### Quản lý Keys
- Admin có thể quản lý keys cho từng sản phẩm
- Keys được tự động gán cho đơn hàng sau khi thanh toán
- Mỗi sản phẩm có thể có nhiều keys (theo số lượng)

### Admin Panel
- Dashboard với thống kê
- Quản lý sản phẩm, danh mục, tin tức
- Quản lý đơn hàng và người dùng
- Xem lịch sử giao dịch của người dùng

## 🔐 Đăng nhập Admin

- **URL**: `http://localhost:3000/admin`
- **Mật khẩu dự phòng**: `141514` (cho tài khoản admin bị khóa)

## 📝 API Endpoints

### Cart
- `POST /api/cart/add/:productId` - Thêm vào giỏ hàng (AJAX)
- `POST /cart/add/:productId` - Thêm vào giỏ hàng
- `POST /cart/remove/:productId` - Xóa khỏi giỏ hàng
- `POST /cart/update/:productId` - Cập nhật số lượng

### Checkout
- `GET /checkout` - Trang xác nhận thanh toán
- `POST /checkout` - Xử lý thanh toán
- `POST /checkout/momo` - Thanh toán MoMo
- `POST /api/momo-callback` - Callback từ MoMo

### Orders
- `GET /orders` - Lịch sử đơn hàng
- `GET /orders/:id/keys` - Xem keys của đơn hàng

## 🗄️ Database Schema

### Bảng chính
- `users` - Người dùng
- `products` - Sản phẩm
	- NEW: `discount_percent` (INTEGER) — Tỷ lệ % khuyến mãi áp dụng lên `price_cents` (mặc định 0)
- `categories` - Danh mục
- `orders` - Đơn hàng
- `order_items` - Chi tiết đơn hàng
- `order_keys` - Keys của đơn hàng
- `wishlist` - Yêu thích
- `news` - Tin tức
- `settings` - Cài đặt
- `sessions` - Session data (PostgreSQL session store)
- `user_carts` - Giỏ hàng theo user_id

## 🛠️ Troubleshooting

### Lỗi kết nối PostgreSQL
- Kiểm tra PostgreSQL service có đang chạy không
- Kiểm tra thông tin trong file `.env`
- Kiểm tra database `safekeys` đã được tạo chưa

### Giỏ hàng bị mất
- Đảm bảo đã chạy `npm run create-user-carts-table`
- Kiểm tra session store có hoạt động không
- Xem log trong console để debug


## 📄 License

ISC

## 👥 Tác giả

SafeKeyS Team
