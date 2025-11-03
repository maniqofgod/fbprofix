# Fix untuk Error Upload 413 (Request Entity Too Large)

## Masalah

Aplikasi mengalami error `413 Request Entity Too Large` saat mengupload file video. Error ini terjadi karena:

1. **Server Node.js** dikonfigurasi untuk menerima file hingga 500MB
2. **Reverse Proxy/Web Server** (nginx/apache) di depan Node.js memiliki batas yang lebih rendah (biasanya 1MB-100MB)
3. Ketika file melebihi batas proxy, proxy mengembalikan HTML error page alih-alih meneruskan ke Node.js
4. Client mencoba parse HTML sebagai JSON dan gagal

## Solusi yang Diterapkan

### 1. Perbaikan Client-Side (app.js)

- ✅ **Validasi ukuran file sebelum upload**: File >100MB akan ditolak di client
- ✅ **Penanganan error 413**: Deteksi status 413 dan tampilkan pesan yang jelas
- ✅ **Penanganan response HTML**: Deteksi response non-JSON dan berikan feedback yang tepat
- ✅ **Error handling yang lebih baik**: Pesan error yang informatif untuk user

### 2. Konfigurasi Server yang Diperlukan

**Untuk Nginx:**
```nginx
# Dalam blok server atau location
client_max_body_size 500m;

# Atau untuk seluruh server
http {
    client_max_body_size 500m;
}
```

**Untuk Apache:**
```apache
# Dalam .htaccess atau konfigurasi virtual host
LimitRequestBody 524288000  # 500MB dalam bytes
```

**Untuk Caddy:**
```caddyfile
# Dalam blok site
request_body {
    max_size 500MB
}
```

## Cara Mengatasi Error Upload

### Jika Anda Administrator Server:

1. **Periksa konfigurasi web server Anda** (nginx/apache/caddy)
2. **Tambahkan/tambah** pengaturan `client_max_body_size` atau `LimitRequestBody`
3. **Restart web server** setelah perubahan konfigurasi
4. **Test upload** dengan file berukuran sedang terlebih dahulu

### Jika Anda User Biasa:

1. **Coba file yang lebih kecil** (<100MB) terlebih dahulu
2. **Pastikan koneksi internet stabil** saat upload
3. **Jika error berlanjut**, hubungi administrator server

## Testing

Untuk memastikan fix berfungsi:

1. Upload file kecil (<10MB) - harus berhasil
2. Upload file sedang (10-500MB) - harus berhasil jika server dikonfigurasi dengan benar
3. Upload file besar (>500MB) - akan ditolak di client dengan pesan jelas
4. Upload file melalui proxy yang tidak dikonfigurasi - akan menampilkan error 413 yang jelas

## Catatan Penting

✅ **DIAGNOSIS SELESAI**: File <1MB berhasil upload, file >1MB gagal. Ini membuktikan masalahnya adalah **web server (nginx/apache) di depan Node.js** yang masih menggunakan batas default 1MB.

### 🚨 **Solusi Definitif:**

**1. Untuk Nginx (Paling Umum):**
```bash
# 1. Cari file konfigurasi nginx
sudo find /etc/nginx -name "*.conf" -exec grep -l "server_name.*fbpro.1337.edu.pl" {} \;

# 2. Edit file konfigurasi yang ditemukan (atau /etc/nginx/sites-available/default)
sudo nano /etc/nginx/sites-available/fbpro

# 3. Tambahkan dalam blok server {}:
client_max_body_size 500m;

# 4. Restart nginx
sudo systemctl restart nginx
```

**2. Untuk Apache:**
```bash
# 1. Edit virtual host atau .htaccess
sudo nano /etc/apache2/sites-available/fbpro.conf

# 2. Tambahkan:
<Directory /var/www/fbpro>
    LimitRequestBody 524288000
</Directory>

# 3. Restart apache
sudo systemctl restart apache2
```

**3. Untuk Caddy:**
```bash
# 1. Edit Caddyfile
sudo nano /etc/caddy/Caddyfile

# 2. Pastikan ada:
fbpro.1337.edu.pl {
    request_body {
        max_size 500MB
    }
    reverse_proxy localhost:3000
}

# 3. Restart caddy
sudo systemctl restart caddy
```

**4. Verifikasi Konfigurasi:**
```bash
# Test konfigurasi nginx
sudo nginx -t

# Atau test apache
sudo apache2ctl configtest

# Restart service yang sesuai
sudo systemctl restart nginx  # atau apache2 atau caddy
```

### 📊 **Testing Setelah Fix:**
1. **Upload file 5MB** → Harus berhasil
2. **Upload file 50MB** → Harus berhasil
3. **Upload file 100MB** → Harus berhasil
4. **Upload file 500MB** → Harus berhasil (batas maksimal)

## File yang Dimodifikasi

- `src/app.js`: Improved error handling in `selectVideoFile()` and `selectBulkVideoFiles()` functions

## Status

✅ **Client-side fix selesai**
⏳ **Server configuration perlu dilakukan oleh administrator**
