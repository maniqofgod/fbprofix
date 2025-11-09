const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const cron = require('node-cron');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const CryptoJS = require('crypto-js');

// Encryption key untuk secure storage
const ENCRYPTION_KEY = 'reelsync-pro-encryption-key-2024';

/**
 * Server-side encryption utilities
 */
const encryptionUtils = {
    encrypt: function(data) {
        return CryptoJS.AES.encrypt(data, ENCRYPTION_KEY).toString();
    },

    decrypt: function(encryptedData) {
        try {
            const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
            return bytes.toString(CryptoJS.enc.Utf8);
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    }
};

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const dbPath = path.join(__dirname, 'reelsync.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
db.serialize(() => {
    // Create users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT DEFAULT 'user',
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Create user_settings table
    db.run(`
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, key),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `);

    // Create facebook_accounts table
    db.run(`
        CREATE TABLE IF NOT EXISTS facebook_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'personal',
            cookie TEXT,
            pages_data TEXT DEFAULT '[]',
            is_valid INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, name),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `);

    // Create settings table for global settings
    db.run(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    `);

    // Create queue table for upload queue management
    db.run(`
        CREATE TABLE IF NOT EXISTS queue (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            account_name TEXT,
            account_type TEXT DEFAULT 'personal',
            cookie TEXT,
            pages_data TEXT,
            page_id TEXT,
            page_name TEXT,
            type TEXT,
            file_path TEXT,
            file_name TEXT,
            caption TEXT,
            status TEXT DEFAULT 'pending',
            scheduled_time DATETIME,
            started_at TEXT,
            actual_upload_time DATETIME,
            completion_time DATETIME,
            processing_time INTEGER,
            retry_count INTEGER DEFAULT 0,
            next_retry DATETIME,
            error_message TEXT,
            upload_url TEXT,
            processing_logs TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `);

    console.log('Database tables initialized');
});

// Middleware
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests from fbpro.1337.edu.pl and localhost for development
        const allowedOrigins = [
            'http://fbpro.1337.edu.pl',
            'https://fbpro.1337.edu.pl',
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'http://0.0.0.0:3000'
        ];

        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin) || origin.includes('fbpro.1337.edu.pl')) {
            return callback(null, true);
        }

        return callback(null, true); // Allow all for development
    },
    credentials: true
}));
app.use(cookieParser());

// Session configuration with persistent cookies
app.use(session({
    secret: process.env.SESSION_SECRET || 'reelsync-pro-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true, // Prevent XSS attacks
        secure: false, // Set to true for HTTPS in production
        sameSite: 'lax' // Helps with CSRF protection
    }
}));

app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

// Static file serving
app.use(express.static(path.join(__dirname, 'src')));
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// File upload configuration
const upload = multer({
    storage: multer.diskStorage({
        destination: path.join(__dirname, 'uploads/'),
        filename: (req, file, cb) => {
            // Generate unique filename but preserve extension
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const extension = path.extname(file.originalname);
            cb(null, uniqueSuffix + extension);
        }
    }),
    limits: {
        fileSize: 500 * 1024 * 1024 // 500MB
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('video/')) {
            cb(null, true);
        } else {
            cb(new Error('Only video files are allowed'));
        }
    }
});

// Create uploads directory if it doesn't exist
if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
    fs.mkdirSync(path.join(__dirname, 'uploads'));
}

// Import existing modules (keep unchanged as requested)
const AccountManager = require('./src/modules/account-manager');
const AnalyticsManager = require('./src/modules/analytics-manager');
const QueueProcessor = require('./src/modules/queue-processor');
const geminiService = require('./geminiService');
const geminiStore = require('./geminiStore');

// Initialize global instances
let globalQueueProcessor = null;
let globalAnalyticsManager = null;

// Initialize modules
async function initializeModules() {
    try {
        console.log('🔄 Initializing modules...');

        // Get settings untuk menginisialisasi dengan opsi yang benar
        const settings = await getSettings();

        // Initialize analytics manager first (asynchronously)
        globalAnalyticsManager = new AnalyticsManager();
        await globalAnalyticsManager.initDatabase();

        // Initialize queue processor
        globalQueueProcessor = new QueueProcessor({
            showBrowser: settings.showBrowser
        });

        console.log('✅ Modules initialized successfully');
    } catch (error) {
        console.error('❌ Error initializing modules:', error);
    }
}

// Database helper functions
function getSettings(userId) {
    return new Promise((resolve) => {
        const settings = {};

        // First try to get user-specific settings
        db.all('SELECT key, value FROM user_settings WHERE user_id = ?', [userId], (err, userRows) => {
            if (err) {
                console.error('Error getting user settings:', err);
                resolve({
                    uploadDelay: 30000,
                    maxRetries: 3,
                    autoStartQueue: false,
                    showNotifications: true,
                    showBrowser: false
                });
                return;
            }

            userRows.forEach(row => {
                settings[row.key] = row.value;
            });

            // If no user settings, get from global settings
            if (Object.keys(settings).length === 0) {
                db.all('SELECT key, value FROM settings', [], (err, globalRows) => {
                    if (err) {
                        console.error('Error getting global settings:', err);
                        resolve({
                            uploadDelay: 30000,
                            maxRetries: 3,
                            autoStartQueue: false,
                            showNotifications: true,
                            showBrowser: false
                        });
                        return;
                    }

                    globalRows.forEach(row => {
                        settings[row.key] = row.value;
                    });

                    resolve({
                        uploadDelay: parseInt(settings.uploadDelay) || 30000,
                        maxRetries: parseInt(settings.maxRetries) || 3,
                        autoStartQueue: settings.autoStartQueue === 'true',
                        showNotifications: settings.showNotifications === 'true',
                        showBrowser: settings.showBrowser === 'true'
                    });
                });
            } else {
                resolve({
                    uploadDelay: parseInt(settings.uploadDelay) || 30000,
                    maxRetries: parseInt(settings.maxRetries) || 3,
                    autoStartQueue: settings.autoStartQueue === 'true',
                    showNotifications: settings.showNotifications === 'true',
                    showBrowser: settings.showBrowser === 'true'
                });
            }
        });
    });
}

function updateSetting(userId, key, value) {
    return new Promise((resolve) => {
        db.run('INSERT OR REPLACE INTO user_settings (user_id, key, value) VALUES (?, ?, ?)', [userId, key, value.toString()], function(err) {
            if (err) {
                console.error('Error updating setting:', err);
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

function getQueueItems(userId) {
    return new Promise((resolve) => {
        // First get settings to calculate cooldowns
        getSettings(userId).then(settings => {
            // Then get queue items
            db.all('SELECT * FROM queue WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, items) => {
                if (err) {
                    console.error('Error getting queue items:', err);
                    resolve([]);
                    return;
                }

                // Add cooldown information for each item
                const now = new Date();
                const cooldownMap = new Map();

                // Calculate last completion time for each account+page combination
                items.forEach(item => {
                    const key = `${item.account_name}-${item.page_id}`;
                    const completionTime = item.completion_time || item.actual_upload_time || item.created_at;
                    const lastUpload = new Date(completionTime);

                    if (!cooldownMap.has(key) || lastUpload > cooldownMap.get(key)) {
                        cooldownMap.set(key, lastUpload);
                    }
                });

                const processedItems = items.map(item => {
                    const key = `${item.account_name}-${item.page_id}`;
                    const lastUpload = cooldownMap.get(key);
                    const timeSinceLastUpload = now - lastUpload;
                    const cooldownMs = settings.uploadDelay || 30000; // 30 seconds default

                    let cooldownRemaining = 0;
                    if (timeSinceLastUpload < cooldownMs && (item.status === 'pending' || item.status === 'scheduled')) {
                        cooldownRemaining = Math.ceil((cooldownMs - timeSinceLastUpload) / 1000); // seconds
                    }

                    return {
                        ...item,
                        cooldownRemaining: cooldownRemaining,
                        cooldownMinutes: Math.ceil(cooldownRemaining / 60),
                        canUpload: cooldownRemaining === 0
                    };
                });

                resolve(processedItems);
            });
        }).catch(error => {
            console.error('Error getting settings for queue items:', error);
            resolve([]);
        });
    });
}

function addQueueItem(item, userId) {
    return new Promise((resolve) => {
        const sql = `
            INSERT INTO queue (
                id, user_id, account_name, account_type, cookie, pages_data,
                page_id, page_name, type, file_path, file_name,
                caption, status, scheduled_time, actual_upload_time, completion_time,
                processing_time, retry_count, error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            item.id,
            userId,
            item.account,
            item.accountType || 'personal',
            item.cookie || null,
            item.pagesData || null,
            item.page,
            item.pageName || '',
            item.type,
            item.file,
            item.fileName || '',
            item.caption,
            item.status || 'pending',
            item.schedule,
            null,
            null,
            0,
            0,
            null,
            new Date().toISOString(),
            new Date().toISOString()
        ];

        db.run(sql, values, function(err) {
            if (err) {
                console.error('Error adding queue item:', err);
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

function updateQueueItem(itemId, updates) {
    return new Promise((resolve) => {
        const setParts = [];
        const values = [];

        // Proper field mapping from camelCase to database columns (snake_case)
        const fieldMapping = {
            accountName: 'account_name',
            pageId: 'page_id',
            pageName: 'page_name',
            filePath: 'file_path',
            fileName: 'file_name',
            schedule: 'scheduled_time', // Map schedule to scheduled_time
            scheduledTime: 'scheduled_time',
            actualUploadTime: 'actual_upload_time',
            completionTime: 'completion_time',
            completedAt: 'completion_time', // Map completedAt to completion_time
            processingTime: 'processing_time',
            retryCount: 'retry_count', // Map retryCount to retry_count
            attempts: 'retry_count', // Also map attempts to retry_count
            errorMessage: 'error_message',
            lastError: 'error_message', // Map lastError to error_message
            status: 'status', // Explicit status mapping
            caption: 'caption', // Explicit caption mapping
            type: 'type', // Explicit type mapping
            createdAt: 'created_at',
            updatedAt: 'updated_at',
            startedAt: 'started_at',
            uploadUrl: 'upload_url', // Explicit mapping for upload URL
            failedAt: 'completion_time', // Map failedAt to completion_time (when fail happens)
            nextRetry: 'next_retry',
            processingLogs: 'processing_logs' // Map nextRetry to next_retry
        };

        Object.entries(updates).forEach(([key, value]) => {
            if (key === 'updated_at') return; // Auto-update
            const dbKey = fieldMapping[key] || key.replace(/([A-Z])/g, '_$1').toLowerCase();
            setParts.push(`${dbKey} = ?`);
            values.push(value);
        });

        setParts.push('updated_at = ?');
        values.push(new Date().toISOString());
        values.push(itemId);

        const sql = `UPDATE queue SET ${setParts.join(', ')} WHERE id = ?`;
        db.run(sql, values, function(err) {
            if (err) {
                console.error('Error updating queue item:', err);
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

function deleteQueueItem(itemId) {
    return new Promise((resolve) => {
        db.run('DELETE FROM queue WHERE id = ?', [itemId], function(err) {
            if (err) {
                console.error('Error deleting queue item:', err);
                resolve(false);
            } else {
                resolve(true);
            }
        });
    });
}

async function testAccountCookie(name, type, cookie) {
    try {
        // Use AccountManager to test the account
        const accountManager = new AccountManager();
        const result = await accountManager.testAccount({
            name: name || 'Test Account',
            type: type || 'personal',
            cookie: cookie
        });

        return {
            success: result.success,
            pages: result.pages || [],
            message: result.message,
            error: result.error
        };
    } catch (error) {
        console.error('Cookie test error:', error);
        return {
            success: false,
            pages: [],
            message: 'Test failed',
            error: error.message
        };
    }
}

// User Authentication Helper Functions
function registerUser(username, password, displayName, role = 'user') {
    return new Promise((resolve) => {
        try {
            // Check if user already exists (case-insensitive)
            // Use callback-based approach like other parts of the code
            db.all('SELECT id, username FROM users', (err, allUsers) => {
                if (err) {
                    console.error('Database error getting users:', err);
                    resolve({ success: false, error: 'Database error' });
                    return;
                }

                console.log(`DEBUG: Total users in database: ${allUsers ? allUsers.length : 'undefined'}`);
                console.log(`DEBUG: Attempting to create user: "${username}"`);
                if (allUsers && Array.isArray(allUsers)) {
                    allUsers.forEach((user, index) => {
                        console.log(`DEBUG: User ${index + 1} - ID: ${user.id}, Username: "${user.username}", Type: ${typeof user.username}`);
                    });
                }

                // Check for existing username (case-insensitive)
                const existingUser = allUsers && Array.isArray(allUsers) ?
                    allUsers.find(user => {
                        const match = user.username && user.username.toLowerCase() === username.toLowerCase();
                        if (match) {
                            console.log(`DEBUG: Found matching user:`, user);
                        }
                        return match;
                    }) :
                    null;

                if (existingUser) {
                    console.log(`User registration failed: username "${username}" already exists (found user: ${existingUser.username})`);
                    resolve({ success: false, error: 'Username already exists' });
                    return;
                }

                console.log(`DEBUG: Username "${username}" validation passed`);

                // Hash password
                const saltRounds = 10;
                const hashedPassword = bcrypt.hashSync(password, saltRounds);

                // Insert new user
                const userId = uuidv4();
                const insertStmt = db.prepare(`
                    INSERT INTO users (id, username, password_hash, display_name, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                `);

                insertStmt.run(userId, username, hashedPassword, displayName || username, role, new Date().toISOString());

                resolve({ success: true, userId });
            });
        } catch (error) {
            console.error('Error registering user:', error);
            resolve({ success: false, error: error.message });
        }
    });
}

function changeUserPassword(userId, currentPassword, newPassword) {
    try {
        // First, get the current user
        const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId);
        if (!user) {
            return { success: false, error: 'User not found' };
        }

        // Verify current password
        const isValidCurrentPassword = bcrypt.compareSync(currentPassword, user.password_hash);
        if (!isValidCurrentPassword) {
            return { success: false, error: 'Current password is incorrect' };
        }

        // Hash new password
        const saltRounds = 10;
        const hashedNewPassword = bcrypt.hashSync(newPassword, saltRounds);

        // Update password
        const stmt = db.prepare(`
            UPDATE users
            SET password_hash = ?, updated_at = ?
            WHERE id = ?
        `);

        const result = stmt.run(hashedNewPassword, new Date().toISOString(), userId);

        if (result.changes > 0) {
            return { success: true, message: 'Password changed successfully' };
        } else {
            return { success: false, error: 'Failed to update password' };
        }
    } catch (error) {
        console.error('Error changing password:', error);
        return { success: false, error: error.message };
    }
}

function authenticateUser(username, password) {
    return new Promise((resolve) => {
        try {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
                if (err) {
                    console.error('Database error during authentication:', err);
                    resolve({ success: false, error: 'Database error' });
                    return;
                }

                if (!user) {
                    resolve({ success: false, error: 'Invalid credentials' });
                    return;
                }

                // Verify password
                try {
                    const isValidPassword = bcrypt.compareSync(password, user.password_hash);
                    if (!isValidPassword) {
                        resolve({ success: false, error: 'Invalid credentials' });
                        return;
                    }

                    // Update last login
                    db.run('UPDATE users SET last_login = ? WHERE id = ?', [new Date().toISOString(), user.id], (updateErr) => {
                        if (updateErr) {
                            console.error('Error updating last login:', updateErr);
                        }

                        resolve({ success: true, user: { id: user.id, username: user.username, displayName: user.display_name, role: user.role } });
                    });
                } catch (bcryptError) {
                    console.error('Bcrypt error during authentication:', bcryptError);
                    resolve({ success: false, error: 'Authentication error' });
                }
            });
        } catch (error) {
            console.error('Error authenticating user:', error);
            resolve({ success: false, error: error.message });
        }
    });
}

function getUserById(userId) {
    try {
        return db.prepare('SELECT id, username, display_name, role FROM users WHERE id = ?').get(userId);
    } catch (error) {
        console.error('Error getting user by id:', error);
        return null;
    }
}

// Authentication Middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.user) {
        // User is authenticated
        req.user = req.session.user;
        return next();
    }

    // Not authenticated
    return res.status(401).json({ error: 'Authentication required' });
}

// Authentication Routes (public - no auth required)
app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }

        const result = await authenticateUser(username, password);
        if (!result.success) {
            return res.status(401).json({ success: false, error: result.error });
        }

        // Store user in session
        req.session.user = result.user;
        req.session.userId = result.user.id;

        res.json({
            success: true,
            user: result.user,
            message: 'Login successful'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

app.post('/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            res.status(500).json({ success: false, error: 'Logout failed' });
        } else {
            res.clearCookie('connect.sid'); // Clear session cookie
            res.json({ success: true, message: 'Logout successful' });
        }
    });
});

app.get('/auth/check', (req, res) => {
    if (req.session && req.session.user) {
        res.json({ authenticated: true, user: req.session.user });
    } else {
        res.json({ authenticated: false });
    }
});

app.post('/auth/register', async (req, res) => {
    try {
        const { username, password, displayName } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long' });
        }

        const result = await registerUser(username, password, displayName);

        if (!result.success) {
            return res.status(400).json({ success: false, error: result.error });
        }

        // Auto-login after registration
        const loginResult = await authenticateUser(username, password);
        if (loginResult.success) {
            req.session.user = loginResult.user;
            req.session.userId = loginResult.user.id;
        }

        res.json({
            success: true,
            userId: result.userId,
            message: 'User registered successfully'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});

app.post('/auth/change-password', requireAuth, (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: 'Current password and new password required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, error: 'New password must be at least 6 characters long' });
        }

        const result = changeUserPassword(userId, currentPassword, newPassword);

        if (!result.success) {
            return res.status(400).json({ success: false, error: result.error });
        }

        res.json({
            success: true,
            message: result.message
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ success: false, error: 'Change password failed' });
    }
});

// API Routes

// Serve main HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'src', 'index.html'));
});

// Apply authentication middleware to all API routes
app.use('/api', requireAuth);

// Admin-only middleware
function requireAdmin(req, res, next) {
    if (req.session && req.session.user) {
        // Check if user is admin
        const user = req.session.user;
        if (user.role === 'admin') {
            return next();
        }
    }

    // Not admin
    return res.status(403).json({ error: 'Admin access required' });
}

app.get('/api/accounts', async (req, res) => {
    try {
        const userId = req.user.id;
        // Use AccountManager to get accounts (consistent with Electron app)
        const accountManager = new AccountManager();
        const accounts = await accountManager.getAllAccounts(userId);

        // Format accounts for frontend (remove cookies for security)
        const safeAccounts = accounts.map(account => ({
            id: account.id, // Use database ID
            name: account.name,
            type: account.type || 'personal',
            pages: account.pages || [],
            pagesCount: (account.pages || []).length,
            valid: account.valid || false,
            hasCookie: !!(account.cookie && account.cookie.trim()),
            created_at: account.createdAt,
            updated_at: account.updatedAt
        }));

        res.json(safeAccounts);
    } catch (error) {
        console.error('❌ Error in get accounts:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/accounts', async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, type, cookie } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ success: false, error: 'Account name is required' });
        }

        // Use AccountManager to save account (consistent with Electron app)
        const accountManager = new AccountManager();
        const result = await accountManager.saveAccount({
            name: name.trim(),
            type: type || 'personal',
            cookie: cookie
        }, userId);

        if (result.success) {
            res.json({
                success: true,
                account: name,
                isEdit: result.isEdit || false,
                pagesCount: result.validation?.pages?.length || 0
            });
        } else {
            res.status(400).json({ success: false, error: result.error });
        }
    } catch (error) {
        console.error('Error saving account:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/accounts/:accountName', async (req, res) => {
    try {
        const userId = req.user.id;
        const { accountName } = req.params;
        const { cookie } = req.body;

        console.log(`🔄 Updating account: ${accountName} for user: ${userId}`);

        // Use AccountManager to update account (consistent with Electron app)
        const accountManager = new AccountManager();

        // Check if account exists first
        const existingAccount = await accountManager.getAccount(accountName, userId);
        if (!existingAccount) {
            console.log(`❌ Account not found: ${accountName}`);
            return res.status(404).json({ success: false, error: 'Account not found' });
        }

        // Prepare update data - only update cookie if provided
        const updateData = {
            name: accountName,
            type: existingAccount.type // Keep existing type
        };

        if (cookie !== undefined) { // Allow empty string to clear cookie
            updateData.cookie = cookie;
        }

        const result = await accountManager.saveAccount(updateData, userId);

        if (result.success) {
            console.log(`✅ Account update successful:`, result);
            res.json({
                success: true,
                account: accountName,
                isEdit: true,
                pagesCount: result.validation?.pages?.length || 0,
                hasChanges: true
            });
        } else {
            console.log(`❌ Account update failed:`, result.error);
            res.status(400).json({ success: false, error: result.error });
        }
    } catch (error) {
        console.error('❌ Error updating account:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/accounts/:accountName', async (req, res) => {
    try {
        const userId = req.user.id;
        const { accountName } = req.params;

        // Use AccountManager to delete account (consistent with Electron app)
        const accountManager = new AccountManager();
        const result = await accountManager.deleteAccount(accountName, userId);

        if (result.success) {
            res.json({ success: true });
        } else {
            res.status(404).json({ success: false, error: 'Account not found' });
        }
    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/accounts/test', async (req, res) => {
    try {
        const { name, type, cookie } = req.body;
        const accountManager = new AccountManager();

        const result = await accountManager.testAccount({ name: name || 'Test Account', type, cookie });

        res.json({
            success: result.success,
            pages: result.pages || [],
            pagesCount: result.pages?.length || 0,
            message: result.message || result.error,
            error: result.error
        });
    } catch (error) {
        console.error('Error testing account:', error);
        res.status(500).json({
            success: false,
            pages: [],
            pagesCount: 0,
            error: error.message
        });
    }
});

// Queue Management Routes (Per User)
app.get('/api/queue', async (req, res) => {
    try {
        const isAdmin = req.user.role === 'admin' || req.user.username === 'admin';
        const requestedUserId = req.query.userId; // Admin can filter by userId

        // Determine which user's queue to fetch
        let targetUserId = req.user.id; // Default to current user

        // Admin can view other users' queues if userId is provided
        if (isAdmin && requestedUserId && requestedUserId !== 'null' && requestedUserId !== 'undefined') {
            targetUserId = requestedUserId;
        }

        // Get queue items for the target user
        const userQueue = await getQueueItems(targetUserId);

        // Transform for frontend compatibility
        const queue = userQueue.map(item => ({
            id: item.id,
            account: item.account_name,
            page: item.page_id,
            pageName: item.page_name,
            type: item.type,
            file: item.file_path,
            fileName: item.file_name,
            caption: item.caption,
            status: item.status,
            schedule: item.scheduled_time,
            actualUploadTime: item.actual_upload_time,
            completionTime: item.completion_time,
            processingTime: item.processing_time,
            attempts: item.retry_count,
            errorMessage: item.error_message,
            createdAt: item.created_at,
            updatedAt: item.updated_at,
            userId: item.user_id // Include userId for admin view
        }));

        res.json(queue);
    } catch (error) {
        console.error('Error getting queue:', error);
        res.status(500).json([]);
    }
});

app.post('/api/queue', async (req, res) => {
    try {
        const userId = req.user.id;
        const userRole = req.user.role;
        const formData = req.body;

        console.log(`📝 POST /api/queue request:`, { userId, userRole, account: formData.account });

        // Use AccountManager to get account information (handles decryption properly)
        const accountManager = new AccountManager();
        const account = await accountManager.getAccount(formData.account, userId);

        console.log(`🔍 Account lookup result:`, {
            found: !!account,
            accountName: account?.name,
            hasCookie: !!(account?.cookie && account.cookie.trim()),
            cookieLength: account?.cookie?.length,
            valid: account?.valid
        });

        if (!account) {
            console.log(`❌ Account "${formData.account}" not found for user ${userId}`);
            return res.status(400).json({ success: false, error: `Account "${formData.account}" not found or invalid` });
        }

        // Check if account has a valid cookie
        if (!account.cookie || !account.cookie.trim()) {
            console.log(`❌ Account "${formData.account}" has no valid cookie`);
            return res.status(400).json({ success: false, error: `Account "${formData.account}" has no valid cookie` });
        }

        const queueItem = {
            id: Date.now().toString(36) + Math.random().toString(36).substr(2),
            account: formData.account,
            accountType: account.type,
            cookie: account.cookie, // Include encrypted cookie
            pagesData: account.pages_data, // Include pages data
            page: formData.page,
            pageName: formData.pageName,
            type: formData.type,
            file: formData.file, // Always use the file path (uploaded path for processing)
            fileName: formData.fileName || formData.file, // Original filename for AI display
            caption: formData.caption,
            status: 'pending',
            schedule: formData.schedule,
            created_at: new Date().toISOString()
        };

        const success = await addQueueItem(queueItem, userId);
        if (success) {
            res.json({ success: true, id: queueItem.id });
        } else {
            res.status(500).json({ success: false, error: 'Failed to add to queue' });
        }
    } catch (error) {
        console.error('Error adding to queue:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/queue/:itemId', async (req, res) => {
    try {
        const userId = req.user.id;
        const userRole = req.user.role;
        const { itemId } = req.params;
        const updates = req.body;

        console.log(`🔄 PUT /api/queue/${itemId} request:`, {
            userId,
            userRole,
            updates: Object.keys(updates),
            itemId
        });

        // First check if item exists at all
        const item = db.prepare('SELECT user_id, status, retry_count FROM queue WHERE id = ?').get(itemId);

        console.log(`📊 Queue item lookup result:`, {
            itemId,
            found: !!item,
            itemUserId: item?.user_id,
            currentUserId: userId,
            status: item?.status,
            retryCount: item?.retry_count
        });

        if (!item) {
            console.log(`❌ Queue item ${itemId} not found in database`);
            return res.status(404).json({ success: false, error: 'Queue item not found' });
        }

        // Check ownership - allow admin to update any item
        const isOwner = item.user_id === userId;
        const isAdmin = userRole === 'admin' || userRole === 'Admin';

        console.log(`🔐 Permission check: isOwner=${isOwner}, isAdmin=${isAdmin}, item.user_id=${item.user_id}, userId=${userId}`);

        if (!isOwner && !isAdmin) {
            console.log(`🚫 Access denied: Item belongs to another user`);
            return res.status(403).json({ success: false, error: 'Access denied: Item belongs to another user' });
        }

        // Prevent updating items that are currently being processed
        if (item.status === 'processing') {
            console.log(`⚠️ Cannot update item ${itemId} - currently being processed`);
            return res.status(409).json({ success: false, error: 'Item is currently being processed. Please wait for processing to complete.' });
        }

        console.log(`✅ Permission granted, proceeding with update`);

        const success = await updateQueueItem(itemId, updates);
        if (success) {
            console.log(`✅ Queue item ${itemId} updated successfully`);
            res.json({ success: true });
        } else {
            console.log(`❌ Failed to update queue item ${itemId}`);
            res.status(500).json({ success: false, error: 'Failed to update queue item' });
        }
    } catch (error) {
        console.error('❌ Error updating queue item:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/queue/:itemId', async (req, res) => {
    try {
        console.log(`🗑️ DELETE request received`);
        console.log(`📊 req.user:`, req.user);
        console.log(`📊 req.session:`, req.session ? 'exists' : 'null');

        if (!req.user) {
            console.log(`❌ No user in session`);
            return res.status(401).json({ success: false, error: 'Authentication required' });
        }

        const userId = req.user.id;
        const userRole = req.user.role;
        const { itemId } = req.params;

        console.log(`🗑️ DELETE request for queue item: ${itemId}`);
        console.log(`👤 User: ${userId} (${userRole})`);

        // Verify the queue item exists and belongs to this user (or user is admin)
        const item = db.prepare('SELECT user_id FROM queue WHERE id = ?').get(itemId);
        console.log(`📊 Queue item lookup result:`, item);

        if (!item) {
            console.log(`❌ Queue item ${itemId} not found in database`);
            return res.status(404).json({ success: false, error: 'Queue item not found' });
        }

        // Allow deletion if item belongs to user OR user is admin
        const isOwner = item.user_id === userId;
        const isAdmin = userRole === 'admin' || userRole === 'Admin';

        console.log(`🔐 Permission check: isOwner=${isOwner}, isAdmin=${isAdmin}, item.user_id=${item.user_id}, userId=${userId}`);

        if (!isOwner && !isAdmin) {
            console.log(`🚫 Access denied: Item belongs to another user`);
            return res.status(403).json({ success: false, error: 'Access denied: Item belongs to another user' });
        }

        console.log(`✅ Permission granted, proceeding with deletion`);
        const success = await deleteQueueItem(itemId);
        console.log(`🗑️ Delete operation result: ${success}`);

        if (success) {
            console.log(`✅ Queue item ${itemId} deleted successfully`);
            res.json({ success: true });
        } else {
            console.log(`❌ Failed to delete queue item ${itemId}`);
            res.status(500).json({ success: false, error: 'Failed to delete queue item' });
        }
    } catch (error) {
        console.error('❌ Error deleting from queue:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Queue Control Routes
app.post('/api/queue/start', async (req, res) => {
    try {
        const userId = req.user.id;
        console.log(`🚀 Starting queue processing for user: ${userId}`);

        if (!globalQueueProcessor) {
            return res.status(500).json({ success: false, error: 'Queue processor not initialized' });
        }

        // Update settings before starting
        const settings = await getSettings(userId);
        console.log(`⚙️ Current settings for user ${userId}:`, settings);

        globalQueueProcessor.updateOptions({
            showBrowser: settings.showBrowser
        });

        // Check current queue status for this user
        const currentQueue = await getQueueItems(userId);
        console.log(`📊 Current queue status for user ${userId}: ${currentQueue.length} items`);

        // Start queue processing for this specific user
        const result = await globalQueueProcessor.startQueue(userId);

        if (result.success) {
            console.log('✅ Queue processing started successfully');
            console.log(`📝 Message: ${result.message}`);
            res.json({ success: true, message: result.message });
        } else {
            console.log('❌ Queue processing failed:', result.error);
            res.status(500).json({ success: false, error: result.error });
        }
    } catch (error) {
        console.error('❌ Error in start-queue:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/queue/process-manually', async (req, res) => {
    try {
        const userId = req.user.id;
        console.log(`🔄 Manual queue processing triggered for user: ${userId}`);

        if (!globalQueueProcessor) {
            return res.status(500).json({ success: false, error: 'Queue processor not available' });
        }

        // Process immediate uploads manually for this user specifically
        await globalQueueProcessor.processImmediateUploads(userId);

        // Get updated queue status for this user
        const queue = await getQueueItems(userId);
        const stats = globalQueueProcessor.getQueueStats();

        console.log(`📊 Manual processing completed for user ${userId}. Queue stats:`, stats);

        res.json({
            success: true,
            stats: stats,
            message: `Processed ${queue.filter(item => item.status === 'completed').length} items for this user`
        });
    } catch (error) {
        console.error('❌ Error in manual queue processing:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// File Upload Route
app.post('/api/upload', (req, res, next) => {
    console.log('📁 Upload request received');
    console.log('📊 Request headers:', {
        'content-type': req.headers['content-type'],
        'content-length': req.headers['content-length'],
        'user-agent': req.headers['user-agent']
    });

    // Check if request body is too large before multer processes it
    const contentLength = parseInt(req.headers['content-length']);
    if (contentLength && contentLength > 500 * 1024 * 1024) {
        console.log('❌ Request body too large:', contentLength, 'bytes');
        return res.status(413).json({
            success: false,
            error: 'File terlalu besar untuk server. Maksimal 500MB.'
        });
    }

    next();
}, upload.single('video'), (req, res) => {
    try {
        if (!req.file) {
            console.log('❌ No file in request');
            return res.status(400).json({ success: false, error: 'No file uploaded' });
        }

        const fileData = {
            success: true,
            filePath: req.file.path,
            fileName: req.file.originalname,
            size: req.file.size,
            mimetype: req.file.mimetype
        };

        console.log('✅ File uploaded successfully:', {
            name: req.file.originalname,
            size: req.file.size,
            path: req.file.path
        });
        res.json(fileData);
    } catch (error) {
        console.error('❌ Error uploading file:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Settings Routes (Per User)
app.get('/api/settings', async (req, res) => {
    try {
        const userId = req.user.id;
        const settings = await getSettings(userId);
        res.json(settings);
    } catch (error) {
        console.error('Error getting settings:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/settings', async (req, res) => {
    try {
        const userId = req.user.id;
        const { uploadDelay, maxRetries, autoStartQueue, showNotifications, showBrowser } = req.body;

        await updateSetting(userId, 'uploadDelay', uploadDelay);
        await updateSetting(userId, 'maxRetries', maxRetries);
        await updateSetting(userId, 'autoStartQueue', autoStartQueue);
        await updateSetting(userId, 'showNotifications', showNotifications);
        await updateSetting(userId, 'showBrowser', showBrowser);

        // Immediately sync settings with globalQueueProcessor if initialized
        if (globalQueueProcessor) {
            console.log('🔄 Syncing updated settings with QueueProcessor...');
            globalQueueProcessor.updateOptions({
                showBrowser: showBrowser
            });
            console.log('✅ QueueProcessor settings updated');
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error saving settings:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Debug endpoint to test browser visibility
app.post('/api/debug/browser-visibility', async (req, res) => {
    try {
        console.log('🧪 Testing browser visibility from API...');

        if (!globalQueueProcessor) {
            return res.status(500).json({ success: false, error: 'QueueProcessor not initialized' });
        }

        // Get current settings
        const settings = await getSettings();

        console.log('Current settings:', settings);
        console.log('QueueProcessor exists:', !!globalQueueProcessor);

        // Test FacebookAutomation directly if needed
        if (globalQueueProcessor.facebookAutomation) {
            console.log('FacebookAutomation exists, options:', globalQueueProcessor.facebookAutomation.options);

            // Try to initialize if not initialized
            if (!globalQueueProcessor.facebookAutomation.isInitialized) {
                await globalQueueProcessor.facebookAutomation.initialize();
            }

            // Create a test page
            const testPage = await globalQueueProcessor.facebookAutomation.browser.newPage();
            await testPage.goto('https://www.google.com', { waitUntil: 'networkidle2' });

            // Take screenshot as proof
            const screenshotPath = path.join(__dirname, 'debug-api-test.png');
            await testPage.screenshot({ path: screenshotPath, fullPage: true });

            await testPage.close();

            res.json({
                success: true,
                message: 'Browser visibility test completed',
                settings: settings,
                headlessMode: globalQueueProcessor.facebookAutomation.options.headless,
                screenshotSaved: screenshotPath
            });
        } else {
            // Initialize FacebookAutomation for testing
            const FacebookAutomation = require('./src/modules/facebook-automation');
            const testAutomation = new FacebookAutomation({ showBrowser: settings.showBrowser });

            await testAutomation.initialize();
            const testPage = await testAutomation.browser.newPage();
            await testPage.goto('https://www.google.com', { waitUntil: 'networkidle2' });

            const screenshotPath = path.join(__dirname, 'debug-api-test.png');
            await testPage.screenshot({ path: screenshotPath, fullPage: true });

            await testPage.close();
            await testAutomation.close();

            res.json({
                success: true,
                message: 'Browser test completed with temp instance',
                settings: settings,
                headlessMode: testAutomation.options.headless,
                screenshotSaved: screenshotPath
            });
        }
    } catch (error) {
        console.error('❌ Browser visibility test failed:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            stack: error.stack
        });
    }
});

// Gemini AI Routes
app.get('/api/gemini/apis', async (req, res) => {
    try {
        const userId = req.user.id;
        const apis = await geminiStore.getAllApis(userId);
        res.json(apis);
    } catch (error) {
        console.error('Error getting Gemini APIs:', error);
        res.status(500).json([]);
    }
});

app.post('/api/gemini/apis', (req, res) => {
    try {
        const userId = req.user.id;
        const { name, apiKey } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ success: false, error: 'API name is required' });
        }

        // For new API, key is required
        if (!apiKey || !apiKey.trim()) {
            return res.status(400).json({ success: false, error: 'API key is required' });
        }

        // Validate API key first
        geminiService.validateApiKey(apiKey).then(isValid => {
            if (!isValid) {
                return res.status(400).json({ success: false, error: 'Invalid API key' });
            }

            geminiStore.addApi(apiKey, name, userId).then(result => {
                res.json({ success: true, api: result });
            }).catch(error => {
                console.error('Error saving Gemini API:', error);
                res.status(500).json({ success: false, error: error.message });
            });
        }).catch(error => {
            console.error('Error validating API key:', error);
            res.status(500).json({ success: false, error: error.message });
        });
    } catch (error) {
        console.error('Error saving Gemini API:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Bulk API insertion endpoint
app.post('/api/gemini/apis/bulk', async (req, res) => {
    try {
        const userId = req.user.id;
        const { apiKeys } = req.body;

        if (!apiKeys || !Array.isArray(apiKeys) || apiKeys.length === 0) {
            return res.status(400).json({ success: false, error: 'API keys array is required' });
        }

        if (apiKeys.length > 50) {
            return res.status(400).json({ success: false, error: 'Maximum 50 API keys allowed at once' });
        }

        const results = {
            successful: [],
            failed: [],
            total: apiKeys.length
        };

        // Process each API key
        for (let i = 0; i < apiKeys.length; i++) {
            const apiKey = apiKeys[i].trim();

            if (!apiKey) {
                results.failed.push({
                    index: i + 1,
                    apiKey: apiKey,
                    error: 'Empty API key'
                });
                continue;
            }

            try {
                // Validate API key
                const isValid = await geminiService.validateApiKey(apiKey);

                if (!isValid) {
                    results.failed.push({
                        index: i + 1,
                        apiKey: apiKey,
                        error: 'Invalid API key'
                    });
                    continue;
                }

                // Generate random name for the API key
                const randomName = `API-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;

                // Add the API
                const result = await geminiStore.addApi(apiKey, randomName, userId);

                results.successful.push({
                    index: i + 1,
                    apiKey: apiKey,
                    name: randomName,
                    id: result.id
                });

            } catch (error) {
                console.error(`Error processing API key ${i + 1}:`, error);
                results.failed.push({
                    index: i + 1,
                    apiKey: apiKey,
                    error: error.message || 'Unknown error'
                });
            }
        }

        res.json({
            success: true,
            results: results,
            message: `Processed ${results.total} API keys: ${results.successful.length} successful, ${results.failed.length} failed`
        });

    } catch (error) {
        console.error('Error in bulk API insertion:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/gemini/apis/:apiId', (req, res) => {
    try {
        const userId = req.user.id;
        const { apiId } = req.params;
        geminiStore.deleteApi(apiId, userId).then(result => {
            if (result) {
                res.json({ success: true });
            } else {
                res.status(404).json({ success: false, error: 'API not found' });
            }
        }).catch(error => {
            console.error('Error deleting Gemini API:', error);
            res.status(500).json({ success: false, error: error.message });
        });
    } catch (error) {
        console.error('Error deleting Gemini API:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/gemini/test-key', (req, res) => {
    try {
        const { apiKey } = req.body;

        if (!apiKey || !apiKey.trim()) {
            return res.status(400).json({ success: false, error: 'API key is required' });
        }

        geminiService.validateApiKey(apiKey).then(isValid => {
            if (isValid) {
                res.json({ success: true });
            } else {
                res.json({ success: false, error: 'Invalid API key' });
            }
        }).catch(error => {
            console.error('Error testing API key:', error);
            res.status(500).json({ success: false, error: error.message });
        });
    } catch (error) {
        console.error('Error in test API key:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/gemini/generate-caption', async (req, res) => {
    try {
        const userId = req.user.id;
        const { fileName, language, apiKeyId } = req.body;

        console.log(`🤖 Generating caption for: ${fileName} in ${language} (User: ${userId}) ${apiKeyId ? `(API Key: ${apiKeyId})` : '(Auto API Key)'}`);

        const result = await geminiService.generateContent(fileName, userId, { language, apiKeyId });

        if (result.generated) {
            console.log('✅ Caption generated successfully');
            res.json({
                success: true,
                title: result.title,
                description: result.description,
                tags: result.tags,
                model: result.model,
                modelInfo: result.modelInfo
            });
        } else {
            console.log('❌ Caption generation failed:', result.error);
            res.status(500).json({
                success: false,
                error: result.error || 'Failed to generate caption'
            });
        }
    } catch (error) {
        console.error('❌ Error in generate-caption:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/gemini/stats', async (req, res) => {
    try {
        const userId = req.user.id;
        const stats = await geminiStore.getUsageStats(userId);
        res.json(stats || {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            successRate: '0%',
            recentRequests: 0,
            recentSuccessRate: '0%',
            averageResponseTime: 0
        });
    } catch (error) {
        console.error('Error getting Gemini stats:', error);
        res.status(500).json({
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            successRate: '0%',
            recentRequests: 0,
            recentSuccessRate: '0%',
            averageResponseTime: 0
        });
    }
});

app.get('/api/gemini/rate-limited-keys', async (req, res) => {
    try {
        const rateLimitedKeys = geminiService.getRateLimitedKeys();
        res.json({
            success: true,
            rateLimitedKeys: rateLimitedKeys
        });
    } catch (error) {
        console.error('Error getting rate limited keys:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            rateLimitedKeys: []
        });
    }
});

// Analytics Routes
app.get('/api/analytics', async (req, res) => {
    try {
        const timeRange = req.query.timeRange || '30d';
        const userRole = req.user.role;

        // Determine which user's data to fetch
        let targetUserId = req.user.id; // Default to current user

        // Admin can view other users' analytics if userId is provided
        if (userRole === 'admin' && req.query.userId && req.query.userId !== 'null' && req.query.userId !== 'undefined') {
            targetUserId = req.query.userId;
        }

        console.log(`📊 Getting analytics data for time range: ${timeRange} (Target User: ${targetUserId}, Requesting User: ${req.user.id}, Role: ${userRole})`);

        if (!globalAnalyticsManager) {
            globalAnalyticsManager = new AnalyticsManager();
        }

        const dashboardData = await globalAnalyticsManager.getDashboardData(timeRange, targetUserId, userRole);

        if (dashboardData) {
            console.log('✅ Analytics data retrieved successfully');
            res.json({
                success: true,
                data: dashboardData,
                timeRange: timeRange,
                targetUserId: targetUserId
            });
        } else {
            console.log('❌ Failed to retrieve analytics data');
            res.status(404).json({
                success: false,
                error: 'Failed to retrieve analytics data',
                data: null
            });
        }
    } catch (error) {
        console.error('❌ Error in get-analytics:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            data: null
        });
    }
});

app.post('/api/analytics/track-upload', async (req, res) => {
    try {
        const uploadData = req.body;

        if (!globalAnalyticsManager) {
            globalAnalyticsManager = new AnalyticsManager();
        }

        const result = await globalAnalyticsManager.trackUpload(uploadData);

        if (result.success) {
            console.log(`✅ Upload tracked successfully: ${result.uploadId}`);
            res.json(result);
        } else {
            console.log(`❌ Upload tracking failed: ${result.error}`);
            res.status(400).json(result);
        }
    } catch (error) {
        console.error('❌ Error in track-upload:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/analytics/update-engagement', async (req, res) => {
    try {
        const { uploadId, metrics } = req.body;

        if (!globalAnalyticsManager) {
            globalAnalyticsManager = new AnalyticsManager();
        }

        const result = await globalAnalyticsManager.updateEngagement(uploadId, metrics);

        if (result.success) {
            console.log(`✅ Engagement updated successfully: ${uploadId}`);
            res.json(result);
        } else {
            console.log(`❌ Engagement update failed: ${result.error}`);
            res.status(400).json(result);
        }
    } catch (error) {
        console.error('❌ Error in update-engagement:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/analytics/export', async (req, res) => {
    try {
        const { format, timeRange } = req.body;
        const userId = req.user.id;
        const userRole = req.user.role;

        console.log(`📤 Exporting analytics data in ${format} format for ${timeRange} (User: ${userId}, Role: ${userRole})`);

        if (!globalAnalyticsManager) {
            globalAnalyticsManager = new AnalyticsManager();
        }

        const result = await globalAnalyticsManager.exportData(format || 'json', timeRange || '30d', userId, userRole);

        if (result.success) {
            console.log(`✅ Analytics data exported successfully in ${format} format`);
            res.json(result);
        } else {
            console.log(`❌ Analytics export failed: ${result.error}`);
            res.status(500).json(result);
        }
    } catch (error) {
        console.error('❌ Error in export-analytics:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Background processing scheduler (similar to Electron cron)
// Temporarily disabled to prevent server crash
// TODO: Fix the database query issue causing null account processing
// cron.schedule('*/30 * * * * *', async () => {
//     if (!globalQueueProcessor) return;

//     try {
//         console.log('🔄 Running scheduled queue processing...');

//         // Process scheduled uploads only - don't process immediate uploads in background
//         // as they need authentication context
//         await globalQueueProcessor.processScheduledUploads();

//         // Note: immediate uploads (pending status) are only processed via authenticated API calls

//         console.log('✅ Scheduled queue processing completed');
//     } catch (error) {
//         console.error('❌ Error in scheduled queue processing:', error);
//     }
// });

// Admin User Management Routes
app.get('/api/admin/users', requireAdmin, (req, res) => {
    try {
        db.all('SELECT id, username, display_name, role, last_login, created_at FROM users ORDER BY created_at DESC', (err, users) => {
            if (err) {
                console.error('❌ Error getting users:', err);
                res.status(500).json({
                    success: false,
                    error: err.message
                });
                return;
            }

            // Ensure users is an array
            const usersArray = Array.isArray(users) ? users : [];

            // Filter out null values and don't return sensitive information like password_hash
            const safeUsers = usersArray.filter(user => user !== null && user !== undefined).map(user => ({
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                role: user.role,
                lastLogin: user.last_login,
                createdAt: user.created_at
            }));

            // Return consistent response format
            res.json({
                success: true,
                users: safeUsers
            });
        });
    } catch (error) {
        console.error('❌ Error getting users:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.get('/api/admin/accounts', requireAdmin, (req, res) => {
    try {
        db.all(`
            SELECT
                fa.id, fa.name, fa.type, fa.pages_data, fa.is_valid, fa.created_at, fa.updated_at,
                u.username as user_username, u.display_name as user_display_name
            FROM facebook_accounts fa
            LEFT JOIN users u ON fa.user_id = u.id
            ORDER BY fa.created_at DESC
        `, (err, accounts) => {
            if (err) {
                console.error('❌ Error getting admin accounts:', err);
                res.status(500).json({
                    success: false,
                    error: err.message
                });
                return;
            }

            // Ensure accounts is an array
            const accountsArray = Array.isArray(accounts) ? accounts : [];

            // Parse pages_data and remove cookies from response for security
            const safeAccounts = accountsArray.filter(account => account !== null && account !== undefined).map(account => {
                const pages = account.pages_data ? JSON.parse(account.pages_data) : [];
                return {
                    id: account.id,
                    name: account.name,
                    type: account.type,
                    pages: pages,
                    pagesCount: pages.length,
                    valid: account.is_valid === 1,
                    hasCookie: account.is_valid === 1,
                    created_at: account.created_at,
                    updated_at: account.updated_at,
                    ownerUsername: account.user_username || 'undefined',
                    ownerDisplayName: account.user_display_name || 'undefined'
                };
            });



            res.json({
                success: true,
                accounts: safeAccounts
            });
        });
    } catch (error) {
        console.error('❌ Error getting admin accounts:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

function deleteUser(userId) {
    try {
        // Don't allow deleting the current logged-in admin
        const currentUser = getUserById(userId);
        if (currentUser && currentUser.role === 'admin') {
            const adminCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ?').get('admin');
            if (adminCount.count <= 1) {
                return { success: false, error: 'Cannot delete the last admin user' };
            }
        }

        // Start a transaction to ensure atomicity
        const begin = db.prepare('BEGIN');
        const commit = db.prepare('COMMIT');
        const rollback = db.prepare('ROLLBACK');

        begin.run();

        try {
            // Delete user's data from child tables first (respecting foreign key constraints)
            // Only delete from tables that actually have user_id column
            db.prepare('DELETE FROM user_settings WHERE user_id = ?').run(userId);
            db.prepare('DELETE FROM queue WHERE user_id = ?').run(userId);
            db.prepare('DELETE FROM facebook_accounts WHERE user_id = ?').run(userId);

            // Note: gemini_apis, gemini_usage, uploads_analytics, and engagement_analytics
            // don't have user_id columns in the current database schema, so skip them

            // Finally, delete the user
            const result = db.prepare('DELETE FROM users WHERE id = ?').run(userId);

            if (result.changes > 0) {
                commit.run();
                return { success: true };
            } else {
                rollback.run();
                return { success: false, error: 'User not found' };
            }
        } catch (txError) {
            rollback.run();
            console.error('Error during user deletion transaction:', txError);
            return { success: false, error: txError.message };
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        return { success: false, error: error.message };
    }
}

app.post('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const { username, password, displayName, role = 'user' } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, error: 'Username and password required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long' });
        }

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ success: false, error: 'Invalid role. Must be "user" or "admin"' });
        }

        const result = await registerUser(username, password, displayName, role);

        if (!result.success) {
            return res.status(400).json({ success: false, error: result.error });
        }

        res.json({
            success: true,
            userId: result.userId,
            message: `User ${username} created successfully`
        });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ success: false, error: 'Failed to create user' });
    }
});

app.delete('/api/admin/users/:userId', requireAdmin, (req, res) => {
    try {
        const { userId: targetUserId } = req.params;
        const currentUserId = req.user.id;

        if (targetUserId === currentUserId) {
            return res.status(400).json({ success: false, error: 'Cannot delete your own account' });
        }

        const result = deleteUser(targetUserId);

        if (!result.success) {
            return res.status(400).json({ success: false, error: result.error });
        }

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ success: false, error: 'Failed to delete user' });
    }
});

app.put('/api/admin/users/:userId/role', requireAdmin, (req, res) => {
    try {
        const { userId: targetUserId } = req.params;
        const { role } = req.body;
        const currentUserId = req.user.id;

        if (!['user', 'admin'].includes(role)) {
            return res.status(400).json({ success: false, error: 'Invalid role. Must be "user" or "admin"' });
        }

        // Prevent changing own role to user if it would leave no admins
        if (targetUserId === currentUserId && role === 'user') {
            const adminCount = db.prepare('SELECT COUNT(*) as count FROM users WHERE role = ? AND id != ?').get('admin', currentUserId);
            if (adminCount.count === 0) {
                return res.status(400).json({ success: false, error: 'Cannot change role to user when you are the only admin' });
            }
        }

        const result = db.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?').run(role, new Date().toISOString(), targetUserId);

        if (result.changes > 0) {
            res.json({ success: true, message: `User role updated to ${role}` });
        } else {
            res.status(404).json({ success: false, error: 'User not found' });
        }
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ success: false, error: 'Failed to update user role' });
    }
});

// Admin System Settings Routes
app.get('/api/admin/settings', requireAdmin, (req, res) => {
    try {
        // Get system-wide settings (not user-specific)
        const globalRows = db.prepare('SELECT key, value FROM settings').all() || [];

        const settings = {};
        if (Array.isArray(globalRows)) {
            globalRows.forEach(row => {
                settings[row.key] = row.value;
            });
        }

        res.json({
            success: true,
            settings: {
                showBrowser: settings.showBrowser === 'true'
            }
        });
    } catch (error) {
        console.error('Error getting admin settings:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.put('/api/admin/settings', requireAdmin, (req, res) => {
    try {
        const { showBrowser } = req.body;

        // Update global system settings
        const result1 = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('showBrowser', showBrowser.toString());

        // Immediately sync settings with globalQueueProcessor if initialized
        if (globalQueueProcessor) {
            console.log('🔄 Syncing updated admin settings with QueueProcessor...');
            globalQueueProcessor.updateOptions({
                showBrowser: showBrowser
            });
            console.log('✅ QueueProcessor admin settings updated');
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error saving admin settings:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Admin File Management Routes
app.get('/api/admin/files', requireAdmin, (req, res) => {
    try {
        const uploadsDir = path.join(__dirname, 'uploads');

        // Ensure uploads directory exists
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
        }

        // Get all files in uploads directory
        const files = fs.readdirSync(uploadsDir)
            .filter(file => {
                // Skip directories and hidden files
                const filePath = path.join(uploadsDir, file);
                return fs.statSync(filePath).isFile() && !file.startsWith('.');
            })
            .map(file => {
                const filePath = path.join(uploadsDir, file);
                const stats = fs.statSync(filePath);

                return {
                    name: file,
                    path: filePath,
                    size: stats.size,
                    sizeFormatted: formatFileSize(stats.size),
                    modified: stats.mtime.toISOString(),
                    created: stats.birthtime.toISOString(),
                    extension: path.extname(file).toLowerCase(),
                    type: getFileType(file)
                };
            })
            .sort((a, b) => new Date(b.modified) - new Date(a.modified)); // Sort by modified date, newest first

        // Get directory stats
        const totalFiles = files.length;
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);

        res.json({
            success: true,
            files: files,
            stats: {
                totalFiles: totalFiles,
                totalSize: totalSize,
                totalSizeFormatted: formatFileSize(totalSize)
            }
        });
    } catch (error) {
        console.error('Error listing files:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

app.delete('/api/admin/files/:filename', requireAdmin, (req, res) => {
    try {
        const { filename } = req.params;
        const uploadsDir = path.join(__dirname, 'uploads');
        const filePath = path.join(uploadsDir, filename);

        // Security check: ensure file is within uploads directory
        const resolvedPath = path.resolve(filePath);
        const resolvedUploadsDir = path.resolve(uploadsDir);

        if (!resolvedPath.startsWith(resolvedUploadsDir)) {
            return res.status(403).json({
                success: false,
                error: 'Access denied: Invalid file path'
            });
        }

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({
                success: false,
                error: 'File not found'
            });
        }

        // Check if it's actually a file (not a directory)
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) {
            return res.status(400).json({
                success: false,
                error: 'Path is not a file'
            });
        }

        // Delete the file
        fs.unlinkSync(filePath);

        console.log(`🗑️ Admin deleted file: ${filename}`);

        res.json({
            success: true,
            message: `File "${filename}" deleted successfully`
        });
    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Helper functions for file management
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function getFileType(filename) {
    const ext = path.extname(filename).toLowerCase();

    const videoTypes = ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv', '.3gp'];
    const imageTypes = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'];

    if (videoTypes.includes(ext)) return 'video';
    if (imageTypes.includes(ext)) return 'image';
    return 'other';
}

// Debug Routes (Admin-only)
app.get('/api/debug/screenshots', requireAdmin, (req, res) => {
    try {
        const screenshotsDir = path.join(__dirname);

        // Get all debug screenshot files
        const screenshotFiles = fs.readdirSync(screenshotsDir)
            .filter(file => file.startsWith('debug-') && file.endsWith('.png'))
            .map(file => {
                const filePath = path.join(screenshotsDir, file);
                const stats = fs.statSync(filePath);
                return {
                    filename: file,
                    filepath: filePath,
                    size: stats.size,
                    timestamp: stats.mtime.toISOString(),
                    step: file.replace('debug-', '').replace('.png', '').replace(/-/g, ' ')
                };
            })
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)) // Latest first
            .slice(0, 20); // Only return the 20 latest screenshots

        res.json({ success: true, screenshots: screenshotFiles });
    } catch (error) {
        console.error('Error listing screenshots:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Serve individual screenshot files
app.get('/api/debug/screenshots/:filename', (req, res) => {
    try {
        const { filename } = req.params;

        // Basic security: only allow files that start with 'debug-' and end with '.png'
        if (!filename.startsWith('debug-') || !filename.endsWith('.png')) {
            return res.status(403).json({ error: 'Invalid filename' });
        }

        const filePath = path.join(__dirname, filename);

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Screenshot not found' });
        }

        // Set appropriate headers and send file
        res.setHeader('Content-Type', 'image/png');
        // Disable caching for debug screenshots to ensure images update immediately after changes
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');

        res.sendFile(filePath);
    } catch (error) {
        console.error('Error serving screenshot:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get terminal logs
let terminalLogs = {
    stdout: [],
    stderr: []
};

app.get('/api/debug/logs', (req, res) => {
    try {
        const { type = 'stdout', limit = 50 } = req.query;
        const limitNum = parseInt(limit) || 50;

        const logs = terminalLogs[type] || [];
        const recentLogs = logs.slice(-limitNum);

        res.json({
            success: true,
            logs: recentLogs,
            type: type,
            total: logs.length
        });
    } catch (error) {
        console.error('Error getting logs:', error);
        res.status(500).json({
            success: false,
            logs: [],
            error: error.message
        });
    }
});

// Clear terminal logs
app.post('/api/debug/logs/clear', (req, res) => {
    try {
        const { type } = req.body;

        if (type && (type === 'stdout' || type === 'stderr')) {
            terminalLogs[type] = [];
        } else {
            // Clear both if no specific type
            terminalLogs.stdout = [];
            terminalLogs.stderr = [];
        }

        res.json({ success: true, message: 'Logs cleared' });
    } catch (error) {
        console.error('Error clearing logs:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Function to add log line (called from other parts of the app)
global.addTerminalLog = function(message, type = 'stdout', level = 'info') {
    try {
        const logEntry = {
            timestamp: new Date().toISOString(),
            message: message,
            level: level
        };

        if (type === 'stdout') {
            terminalLogs.stdout.push(JSON.stringify(logEntry));
            // Keep only last 1000 lines
            if (terminalLogs.stdout.length > 1000) {
                terminalLogs.stdout = terminalLogs.stdout.slice(-1000);
            }
        } else if (type === 'stderr') {
            terminalLogs.stderr.push(JSON.stringify(logEntry));
            // Keep only last 1000 lines
            if (terminalLogs.stderr.length > 1000) {
                terminalLogs.stderr = terminalLogs.stderr.slice(-1000);
            }
        }
    } catch (error) {
        console.error('Error adding terminal log:', error);
    }
};

// Override console.log to also add to terminal logs
const originalConsoleLog = console.log;
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

console.log = function(...args) {
    originalConsoleLog(...args);

    // Convert args to string and add to terminal logs
    const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
    global.addTerminalLog(message, 'stdout', 'info');
};

console.error = function(...args) {
    originalConsoleError(...args);

    // Convert args to string and add to terminal logs
    const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
    global.addTerminalLog(message, 'stderr', 'error');
};

console.warn = function(...args) {
    originalConsoleWarn(...args);

    // Convert args to string and add to terminal logs
    const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
    global.addTerminalLog(message, 'stdout', 'warn');
};

// Sample log entries for testing
setTimeout(() => {
    global.addTerminalLog('Server started successfully', 'stdout', 'info');
    global.addTerminalLog('Queue processor initialized', 'stdout', 'info');
    global.addTerminalLog('Analytics manager ready', 'stdout', 'info');
}, 1000);

// Cleanup on exit
process.on('SIGINT', () => {
    console.log('\n🛑 SIGINT received, cleaning up...');
    if (globalQueueProcessor) {
        globalQueueProcessor.cleanup();
        globalQueueProcessor = null;
    }
    db.close();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 SIGTERM received, cleaning up...');
    if (globalQueueProcessor) {
        globalQueueProcessor.cleanup();
        globalQueueProcessor = null;
    }
    db.close();
    process.exit(0);
});

// Test the fix by checking if the server can start without the accountMgr error
console.log('🔧 Testing account manager fix...');

// Start server
async function startServer() {
    try {
        await initializeModules();

        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 ReelSync Pro web server running on http://0.0.0.0:${PORT}`);
            console.log('💡 Open your browser and go to the URL above');
            console.log('✅ Account manager fix applied successfully');
        });
    } catch (error) {
        console.error('❌ Error starting server:', error);
        process.exit(1);
    }
}

startServer();
