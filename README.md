# ReelSync Pro

**Aplikasi Desktop Professional untuk Otomasi Unggahan Facebook Reels & Video Posts**

![ReelSync Pro](assets/icon.png)

ReelSync Pro adalah aplikasi desktop lintas platform yang dirancang untuk mengotomatiskan proses upload video ke Facebook dengan interface yang intuitif dan fitur yang powerful.

## ✨ Fitur Utama

### 🔐 **Manajemen Akun Facebook**
- ✅ Multi-account management dengan secure cookie authentication
- ✅ Automatic cookie validation dengan real-time page discovery
- ✅ Encrypted storage dengan AES encryption
- ✅ Account status monitoring dan auto-revalidation

### 🎬 **Upload Automation**
- ✅ Support untuk Facebook Reels dan Video Posts
- ✅ Drag & drop file picker dengan multiple format support
- ✅ Rich caption editor dengan scheduling options
- ✅ Queue management dengan real-time progress tracking

#### 🔄 **Facebook Navigation Flow**
**Important**: For successful uploads, the app follows the correct Facebook navigation sequence:

**For Reels Upload:**
1. **First**: Navigate to profile page: `https://www.facebook.com/profile.php?id=PAGE_ID`
2. **Then**: Navigate to Reels creation: `https://www.facebook.com/reels/create`
3. **Upload video** and wait for processing
4. **Click "Berikutnya"** (Next) button
5. **Fill caption** in the text editor
6. **Click "Berikutnya"** again
7. **Click "Posting"** to publish

**For Video Posts:**
1. **First**: Navigate to profile page: `https://www.facebook.com/profile.php?id=PAGE_ID`
2. **Then**: Navigate to Facebook main page: `https://www.facebook.com/`
3. **Create new post** and upload video
4. **Click "Berikutnya"** (Next) button
5. **Fill caption** in the text editor
6. **Click "Posting"** to publish

This ensures proper authentication and page access before uploading.

### ⏰ **Advanced Scheduling**
- ✅ Date/time picker untuk scheduled uploads
- ✅ Automatic retry mechanism dengan exponential backoff
- ✅ Queue priority system dan batch processing
- ✅ Cron-based background processing

### 🔧 **Professional Interface**
- ✅ Modern tabbed interface dengan responsive design
- ✅ Real-time notifications dan toast messages
- ✅ Comprehensive logging system
- ✅ Dark/Light theme support

### 🛡️ **Security & Privacy**
- ✅ Context isolation untuk maximum security
- ✅ No password storage (cookie-based authentication)
- ✅ Secure IPC communication
- ✅ Input validation dan sanitization

## 🚀 Instalasi

### Prerequisites
- Node.js 16+
- npm atau yarn
- Windows 10/11, macOS, atau Linux

### Quick Start
```bash
# Clone atau download project
git clone [repository-url]
cd reelsync-pro

# Install dependencies
npm install

# Run development mode
npm start

# Run tests
npm test

# Build untuk production
npm run build
```

## 🌐 Server Configuration (Nginx)

### Nginx Configuration for Production Deployment

```nginx
server {
    server_name fbpro.1337.edu.pl;
    client_max_body_size 500m;

    # Main application
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # API routes
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static assets
    location /assets/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/fbpro.1337.edu.pl/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/fbpro.1337.edu.pl/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot

}
server {
    if ($host = fbpro.1337.edu.pl) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


    server_name fbpro.1337.edu.pl;

    listen 80;
    return 404; # managed by Certbot


}
```

### Nginx Configuration Features:
- **SSL/TLS**: HTTPS dengan Let's Encrypt certificates
- **Large File Uploads**: `client_max_body_size 500m` untuk video uploads
- **Proxy Settings**: Proper header forwarding untuk aplikasi Node.js
- **Caching**: Static assets caching untuk performance
- **Security**: HTTPS redirect dan secure headers

### Deployment Steps:
1. **Install Nginx**: `sudo apt install nginx`
2. **Configure SSL**: Gunakan Certbot untuk Let's Encrypt
3. **Copy config**: Salin konfigurasi di atas ke `/etc/nginx/sites-available/fbpro.1337.edu.pl.conf`
4. **Enable site**: `sudo ln -s /etc/nginx/sites-available/fbpro.1337.edu.pl.conf /etc/nginx/sites-enabled/`
5. **Test config**: `sudo nginx -t`
6. **Restart Nginx**: `sudo systemctl restart nginx`

## 📖 Cara Penggunaan

### 1. Setup Akun Facebook
1. **Buka aplikasi** dan pergi ke tab "Manajemen Akun"
2. **Klik "Tambah Akun"** dan isi nama akun
3. **Dapatkan Cookie Facebook**:
   - Buka Facebook di browser Chrome/Firefox
   - Tekan F12 → Application → Cookies → https://www.facebook.com
   - Copy semua cookie data
4. **Paste cookie** dan klik "Simpan & Validasi"
5. **Sistem akan otomatis** mengambil data halaman yang Anda kelola

### 2. Upload Video
1. **Pergi ke tab "Upload Video Baru"**
2. **Pilih akun dan halaman** dari dropdown
3. **Pilih jenis upload** (Reels atau Video Post)
4. **Select file video** dengan drag & drop atau file picker
5. **Isi caption** (opsional)
6. **Atur jadwal** (opsional untuk upload langsung)
7. **Klik "Tambahkan ke Antrian"**

### 3. Monitor Progress
1. **Tab "Status Antrian"** untuk melihat semua uploads
2. **Real-time statistics** (Menunggu, Diproses, Selesai, Gagal)
3. **Queue controls** (Start, Pause, Clear)
4. **Tab "Log Aktivitas"** untuk monitoring detail

## 🛠️ Development

### Project Structure
```
reelsync-pro/
├── main.js                    # Main Electron process
├── preload.js                 # Secure API bridge
├── package.json              # Dependencies & configuration
├── src/
│   ├── index.html            # Main UI
│   ├── styles.css            # Styling & responsive design
│   ├── app.js                # Frontend logic
│   └── modules/              # Backend modules
│       ├── account-manager.js      # Account management
│       ├── queue-processor.js       # Queue & scheduling
│       └── facebook-automation.js  # Puppeteer automation
├── assets/
│   ├── icon.png              # Application icon
│   ├── icon-256.png          # High-res icon
│   └── icon-*.png            # Icon variants
├── scripts/
│   ├── test-app.js           # Application tests
│   ├── test-facebook-cookies.js    # Cookie tests
│   ├── run-all-poc.js        # POC runner
│   ├── cookie-helper.js      # Cookie utilities
│   └── create-icon.js        # Icon generator
└── dist/                     # Build output
```

### Tech Stack
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Electron.js, Node.js
- **Automation**: Puppeteer (headless Chrome)
- **Storage**: electron-store (encrypted local storage)
- **Scheduling**: node-cron
- **Security**: Context isolation, AES encryption

### Available Scripts
```bash
npm start              # Run aplikasi
npm run dev           # Development mode
npm test              # Run all tests
npm run test-app      # Application tests only
npm run test-cookies  # Facebook cookies tests
npm run build         # Build semua platform
npm run build-win     # Windows installer only
npm run build-mac     # macOS installer only
npm run build-linux   # Linux package only
```

## 🔧 Configuration

### Pengaturan Aplikasi
- **Upload Delay**: 10-300 detik (default: 30s)
- **Max Retries**: 1-5 attempts (default: 3)
- **Auto-start Queue**: Enable/disable
- **Notifications**: Toast notifications

### Facebook Cookie Setup
```bash
# Use cookie helper untuk setup
node scripts/cookie-helper.js

# Atau manual setup di aplikasi
# Tab Manajemen Akun → Tambah Akun → Test Cookie
```

## 📊 Build & Distribution

### Production Ready
- ✅ **Windows Installer**: NSIS setup (72.8 MB)
- ✅ **Code Signed**: Ready untuk distribution
- ✅ **Auto-updater**: Built-in update mechanism
- ✅ **Multi-platform**: Windows, macOS, Linux

### Installation Package
```
📦 ReelSync Pro Setup 1.0.0.exe
📍 Location: dist/ReelSync Pro Setup 1.0.0.exe
🔧 Size: 72.8 MB
📋 Type: Windows Installer (NSIS)
```

## 🧪 Testing

### Test Coverage
```bash
# Complete test suite
npm test

# Individual test components
npm run test-app        # Core application tests
npm run test-cookies   # Facebook cookies tests
```

### Test Results
```
📊 Application Tests: 8/8 PASSED ✅
📊 Integration Tests: 2/2 PASSED ✅
📊 Cookie Tests: 5/5 PASSED ✅
📊 Total: 15/15 PASSED ✅
```

## 🔒 Security

### Authentication
- ✅ Cookie-based authentication (no password storage)
- ✅ AES encryption untuk sensitive data
- ✅ Context isolation (renderer security)
- ✅ Secure IPC communication
- ✅ Input validation dan sanitization

### Data Protection
- ✅ Encrypted local storage
- ✅ No sensitive data exposure di frontend
- ✅ Secure file handling
- ✅ Memory cleanup setelah use

## 📚 Documentation

### User Guide
- **Installation**: Step-by-step setup guide
- **Cookie Setup**: Comprehensive Facebook cookie tutorial
- **Upload Process**: Complete workflow documentation
- **Troubleshooting**: Common issues dan solutions

### Developer Documentation
- **API Reference**: Complete module documentation
- **Architecture**: System design overview
- **Contributing**: Development guidelines
- **Deployment**: Production deployment guide

## 🤝 Contributing

### Development Setup
1. Fork repository
2. Create feature branch
3. Install dependencies: `npm install`
4. Run tests: `npm test`
5. Make changes dengan proper testing
6. Submit pull request

### Code Standards
- ESLint configuration enforced
- Prettier formatting required
- Comprehensive test coverage
- Documentation untuk all new features

## 📄 License

MIT License - lihat file LICENSE untuk detail lengkap.

## 🙏 Acknowledgments

- **Electron.js Team** untuk excellent framework
- **Puppeteer Team** untuk browser automation
- **Open Source Community** untuk tools dan libraries
- **Beta Testers** untuk valuable feedback

## 📞 Support

### Getting Help
- **Documentation**: Baca README dan PROJECT-SUMMARY.md
- **Issues**: GitHub Issues untuk bug reports
- **Discussions**: GitHub Discussions untuk questions
- **Email**: support@supernovacorp.com

### Troubleshooting
1. **Check logs** di tab "Log Aktivitas"
2. **Verify cookies** dengan cookie helper script
3. **Restart aplikasi** jika diperlukan
4. **Clear cache** jika mengalami issues

## 🔄 Update & Maintenance

- **Auto-update**: Built-in update mechanism
- **Backup**: Export account data regularly
- **Monitor**: Check Facebook API changes
- **Security**: Regular dependency updates

---

**ReelSync Pro** - Professional Facebook Video Upload Automation
**Version**: 1.0.0
**Status**: Production Ready ✅
**Last Updated**: 2024

*Dibuat dengan ❤️ untuk content creators dan social media managers*
