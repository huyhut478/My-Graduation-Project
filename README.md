# SafeKeyS – Hệ thống bán key phần mềm và game

---
## I. DEMO 
### Trang chủ
<img width="1000" height="800" alt="image" src="https://github.com/user-attachments/assets/aa32dfd9-d578-4d7e-8730-2f283c981182" />

### Danh sách và chi tiết sản phẩm
<img width="750" height="800" alt="image" src="https://github.com/user-attachments/assets/99fb84f6-3fdb-4adb-a854-d1ccad788b52" />

### Giỏ hàng và Thanh toán
<img width="570" height="580" alt="image" src="https://github.com/user-attachments/assets/84ba8e31-d76e-4872-b8de-bbf9b575a4ba" />

### Admin Panel
<img width="1000" height="500" alt="image" src="https://github.com/user-attachments/assets/037c0fbc-c95a-4250-ba3a-4d1a8a26e490" />

## II. MÔ TẢ HỆ THỐNG

SafeKeyS là hệ thống bán key phần mềm và game, hỗ trợ đầy đủ các chức năng quản lý sản phẩm, đơn hàng, thanh toán điện tử và lưu trữ dữ liệu an toàn trên PostgreSQL.

### 1. Tính năng chính
- Quản lý sản phẩm: thêm, sửa, xóa và phân loại theo danh mục  
- Quản lý đơn hàng và trạng thái xử lý  
- Thanh toán MoMo tích hợp trực tiếp  
- Giỏ hàng lưu trong database, không mất khi đăng xuất  
- Quản lý người dùng: đăng ký, đăng nhập, chỉnh sửa hồ sơ  
- Danh sách sản phẩm yêu thích  
- Quản lý tin tức, bài viết  
- Admin Panel với dashboard quản lý tổng thể  
- Dữ liệu lưu trữ bằng PostgreSQL

### 2. Cấu trúc dữ liệu
Hệ thống sử dụng PostgreSQL để lưu:
- Users  
- Products  
- Categories  
- Orders  
- Order Items  
- Order Keys  
- Wishlist  
- Sessions  
- User Carts  

### 3. Admin Panel
- Quản lý sản phẩm, danh mục, tin tức  
- Quản lý đơn hàng và người dùng  
- Thống kê doanh thu  
- Hỗ trợ mật khẩu dự phòng khi admin bị khóa  

---

## III. HƯỚNG DẪN CÀI ĐẶT VÀ SỬ DỤNG

---

### 1. Yêu cầu hệ thống
- Node.js 18 trở lên  
- PostgreSQL 12 trở lên  
- npm 

---

### 2. Cài đặt dự án

Clone project:
```bash
git clone <repository-url>
cd SafeKeyS
````

Cài dependencies:

```bash
npm install
```

---

### 3. Cấu hình môi trường (.env)

Tạo file `.env` tại thư mục gốc:

```env
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=safekeys
PG_USER=postgres
PG_PASSWORD=your_database_password

PORT=3000
NODE_ENV=development
SESSION_SECRET=your_session_secret_key_here

MOMO_ACCESS_KEY=
MOMO_SECRET_KEY=
MOMO_PARTNER_CODE=MOMO
MOMO_REQUEST_TYPE=captureWallet
MOMO_LANG=vi

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=

OTP_EXPIRE_SECONDS=120
```

---

### 4. Tạo database

Tạo tự động:

```bash
npm run create-db
```

### 5. Chạy hệ thống

Development:

```bash
npm run dev
```

Truy cập:

```
http://localhost:3000
```

---

### 6. Đăng nhập Admin

* URL Admin: `http://localhost:3000/admin`

---

## Troubleshooting

### Không kết nối PostgreSQL

* Kiểm tra PostgreSQL đã chạy chưa
* Kiểm tra thông tin `.env`
* Kiểm tra database đã tồn tại

### Giỏ hàng bị mất

* Kiểm tra session store
* Kiểm tra log console

---


