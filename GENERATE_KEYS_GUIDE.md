# 🔑 Generate Product Keys Script

Script độc lập để tạo keys cho sản phẩm. **Không ảnh hưởng đến ứng dụng chính**.

## 📋 Mục Đích

- Tạo tự động keys cho sản phẩm dựa trên tồn kho
- Hỗ trợ 3 format key khác nhau
- Chạy độc lập via npm command
- Không can thiệp vào server chính

## 🚀 Cách Sử Dụng

### 1. **Cách Đơn Giản Nhất** (Tạo keys = tồn kho)
```bash
npm run generate-keys
```
- Sẽ scan tất cả sản phẩm đang hoạt động
- Tạo keys sao cho số lượng = tồn kho

### 2. **Tạo Keys với Format Khác**
```bash
# Format UUID
npm run generate-keys --format UUID

# Format SHORT (8 ký tự)
npm run generate-keys --format SHORT
```

### 3. **Tạo Số Lượng Keys Cố Định**
```bash
# Tạo 20 keys cho mỗi sản phẩm
npm run generate-keys --strategy custom --count 20

# Tạo 50 keys
npm run generate-keys --strategy custom --count 50
```

### 4. **Chỉ Tạo Keys cho Sản Phẩm Cụ Thể**
```bash
# Chỉ sản phẩm #1, #2, #3
npm run generate-keys --products 1,2,3

# Kết hợp với format
npm run generate-keys --format UUID --products 5,10,15
```

### 5. **Kết Hợp Tất Cả Tùy Chọn**
```bash
npm run generate-keys --format SHORT --strategy custom --count 50 --products 1,2,3
```

## 🔑 Format Keys

| Format | Ví Dụ | Độ Dài | Thích Hợp |
|--------|-------|--------|----------|
| **FULL** | `A1B2-C3D4-E5F6-G7H8` | 16 ký tự | Mặc định, an toàn |
| **SHORT** | `A1B2C3D4` | 8 ký tự | Key ngắn, gọi nhẹ |
| **UUID** | `A1B2C3D4-E5F6-G7H8-I9J0-K1L2M3N4O5P6` | 36 ký tự | Standard UUID format |

## 📊 Strategy

### **stock** (Mặc định)
- Tạo keys = tồn kho sản phẩm
- Ví dụ: Sản phẩm có 100 tồn kho → tạo 100 keys

### **custom**
- Tạo số lượng keys chỉ định
- Dùng tham số `--count`
- Ví dụ: Tạo 50 keys cho mỗi sản phẩm

## 📝 Ví Dụ Thực Tế

### Tình Huống 1: Thêm Keys Cho Sản Phẩm Mới
```bash
# Sản phẩm #10 có 100 tồn kho, cần 100 keys
npm run generate-keys --products 10
```

### Tình Huống 2: Tạo Hàng Loạt Keys
```bash
# Tạo 500 keys cho sản phẩm #1 (Windows License)
npm run generate-keys --strategy custom --count 500 --products 1
```

### Tình Huống 3: Cập Nhật Tất Cả Sản Phẩm
```bash
# Đảm bảo tất cả sản phẩm đều có keys = tồn kho
npm run generate-keys
```

### Tình Huống 4: Format UUID cho Khóa Cấp Cao
```bash
# Tạo keys dạng UUID cho enterprise products
npm run generate-keys --format UUID --products 5,10,15
```

## 💾 Dữ Liệu Được Lưu

Keys được lưu vào bảng `product_keys`:
- `id` - ID key (auto-increment)
- `product_id` - ID sản phẩm
- `key_value` - Giá trị key (duy nhất, không trùng)
- `created_at` - Thời gian tạo
- `deleted_at` - NULL (chưa được sử dụng)

## ✅ Kiểm Tra Kết Quả

### Trong Database
```sql
-- Xem tổng keys
SELECT product_id, COUNT(*) as key_count 
FROM product_keys 
WHERE deleted_at IS NULL 
GROUP BY product_id;

-- Xem keys của sản phẩm #1
SELECT key_value, created_at 
FROM product_keys 
WHERE product_id = 1 AND deleted_at IS NULL;
```

### Qua Admin Panel
- Vào **Admin → Keys Management**
- Xem keys đã được tạo cho từng sản phẩm

## ⚠️ Lưu Ý

1. **Không tạo trùng** - Script tự động kiểm tra để tránh keys trùng
2. **Idempotent** - Chạy lại script không tạo keys thêm nếu đủ
3. **Transaction** - Tất cả keys được tạo trong một transaction
4. **An toàn** - Không ảnh hưởng đến server chính
5. **Offline** - Có thể chạy khi server đang chạy

## 🐛 Troubleshooting

### "❌ Connection refused"
```bash
# Kiểm tra PostgreSQL có chạy không
# Hoặc cấu hình .env
cat .env | grep PG_
```

### "❌ Database does not exist"
```bash
# Tạo database trước
createdb safekeys
```

### "❌ Column product_keys does not exist"
```bash
# Chạy migration để tạo bảng
npm run sync-to-files
```

### Muốn xem chi tiết (Debug)?
```bash
# Xem logs chi tiết
npm run generate-keys -- --help
```

## 📞 Hỗ Trợ

### Kiểm tra môi trường
```bash
# Xem config
node -e "console.log(process.env.PG_HOST, process.env.PG_DATABASE, process.env.PG_USER)"
```

### Rollback (Nếu cần xóa keys)
```sql
-- ⚠️ CẢNH BÁO: Xóa tất cả keys chưa sử dụng
DELETE FROM product_keys WHERE deleted_at IS NULL;

-- Hoặc xóa keys của sản phẩm cụ thể (#1)
DELETE FROM product_keys WHERE product_id = 1 AND deleted_at IS NULL;
```

## 🎯 Best Practices

1. **Lần Đầu**: Chạy `npm run generate-keys` để tạo keys = tồn kho
2. **Khi Thêm Sản Phẩm**: `npm run generate-keys --products [NEW_ID]`
3. **Batch Update**: `npm run generate-keys --strategy custom --count 1000`
4. **Kiểm Tra**: `SELECT COUNT(*) FROM product_keys WHERE deleted_at IS NULL`

---

**Script Location**: `/data/generate-keys.js`  
**Config**: Tự động từ `.env`  
**Database**: PostgreSQL  
**Runtime**: ~5-30 giây (tùy số lượng sản phẩm)
