const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const CryptoJS = require('crypto-js');

// Database setup
const dbPath = path.join(__dirname, '../../reelsync.db');
const db = new sqlite3.Database(dbPath);

// Encryption key untuk secure storage
const ENCRYPTION_KEY = 'reelsync-pro-encryption-key-2024';

/**
 * Account Manager Module
 * Menangani semua operasi terkait manajemen akun Facebook
 * Now uses SQLite database instead of electron-store
 */
class AccountManager {
    constructor() {
        this.db = db;
        this.encryptionKey = ENCRYPTION_KEY;

        // Initialize database table
        this.initializeTable();
    }

    initializeTable() {
        this.db.run(`
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
                UNIQUE(user_id, name)
            )
        `);
    }

    /**
     * Encrypt data menggunakan AES
     */
    encrypt(data) {
        return CryptoJS.AES.encrypt(data, this.encryptionKey).toString();
    }

    /**
     * Decrypt data menggunakan AES
     */
    decrypt(encryptedData) {
        try {
            const bytes = CryptoJS.AES.decrypt(encryptedData, this.encryptionKey);
            return bytes.toString(CryptoJS.enc.Utf8);
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    }

    /**
     * Simpan akun baru atau update akun existing
     */
    async saveAccount(accountData, userId = 'default') {
        return new Promise((resolve) => {
            try {
                // Check if account already exists
                this.db.get('SELECT id, cookie, pages_data, is_valid FROM facebook_accounts WHERE user_id = ? AND name = ?', [userId, accountData.name], (err, existingAccount) => {
                    if (err) {
                        console.error('Error checking existing account:', err);
                        resolve({ success: false, error: err.message });
                        return;
                    }

                    const isEdit = !!existingAccount;
                    let encryptedCookie = existingAccount ? existingAccount.cookie : null;
                    let pagesData = existingAccount ? existingAccount.pages_data : '[]';
                    let isValid = existingAccount ? existingAccount.is_valid : 0;

                    // Encrypt cookie if provided
                    if (accountData.cookie && accountData.cookie.trim()) {
                        encryptedCookie = this.encrypt(accountData.cookie);
                        isValid = 0; // Need re-validation
                        pagesData = '[]';
                    }

                    if (isEdit) {
                        // Update existing account
                        this.db.run(
                            'UPDATE facebook_accounts SET type = ?, cookie = ?, pages_data = ?, is_valid = ?, updated_at = ? WHERE user_id = ? AND name = ?',
                            [accountData.type || 'personal', encryptedCookie, pagesData, isValid, new Date().toISOString(), userId, accountData.name],
                            async (updateErr) => {
                                if (updateErr) {
                                    console.error('Error updating account:', updateErr);
                                    resolve({ success: false, error: updateErr.message });
                                    return;
                                }

                                // Validate account if cookie was updated
                                let validationResult = null;
                                if (accountData.cookie && accountData.cookie.trim()) {
                                    validationResult = await this.validateAccount(accountData.name, userId);
                                }

                                resolve({
                                    success: true,
                                    account: accountData.name,
                                    validation: validationResult,
                                    isEdit: true
                                });
                            }
                        );
                    } else {
                        // New account - cookie required
                        if (!accountData.cookie || !accountData.cookie.trim()) {
                            resolve({
                                success: false,
                                error: 'Cookie diperlukan untuk akun baru'
                            });
                            return;
                        }

                        // Insert new account
                        this.db.run(
                            'INSERT INTO facebook_accounts (user_id, name, type, cookie, pages_data, is_valid, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                            [userId, accountData.name, accountData.type || 'personal', encryptedCookie, pagesData, isValid, new Date().toISOString(), new Date().toISOString()],
                            async (insertErr) => {
                                if (insertErr) {
                                    console.error('Error inserting account:', insertErr);
                                    resolve({ success: false, error: insertErr.message });
                                    return;
                                }

                                // Validate new account
                                const validationResult = await this.validateAccount(accountData.name, userId);

                                resolve({
                                    success: true,
                                    account: accountData.name,
                                    validation: validationResult,
                                    isEdit: false
                                });
                            }
                        );
                    }
                });
            } catch (error) {
                console.error('Error saving account:', error);
                resolve({ success: false, error: error.message });
            }
        });
    }

    /**
     * Hapus akun
     */
    async deleteAccount(accountName, userId = 'default') {
        return new Promise((resolve) => {
            try {
                this.db.run('DELETE FROM facebook_accounts WHERE user_id = ? AND name = ?', [userId, accountName], function(err) {
                    if (err) {
                        console.error('Error deleting account:', err);
                        resolve({ success: false, error: err.message });
                        return;
                    }

                    if (this.changes > 0) {
                        resolve({
                            success: true,
                            message: `Akun ${accountName} berhasil dihapus`
                        });
                    } else {
                        resolve({ success: false, error: 'Akun tidak ditemukan' });
                    }
                });
            } catch (error) {
                console.error('Error deleting account:', error);
                resolve({ success: false, error: error.message });
            }
        });
    }

    /**
      * Ambil semua akun
      */
    getAllAccounts(userId = 'default') {
        return new Promise((resolve) => {
            try {
                this.db.all('SELECT * FROM facebook_accounts WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
                    if (err) {
                        console.error('Error getting accounts:', err);
                        resolve([]);
                        return;
                    }

                    // Decrypt cookies untuk setiap akun dan format data
                    const accounts = rows.map(account => ({
                        id: account.id,
                        name: account.name,
                        type: account.type || 'personal',
                        cookie: this.decrypt(account.cookie),
                        pages: account.pages_data ? JSON.parse(account.pages_data) : [],
                        valid: account.is_valid === 1,
                        createdAt: account.created_at,
                        updatedAt: account.updated_at
                    }));

                    resolve(accounts);
                });
            } catch (error) {
                console.error('Error getting accounts:', error);
                resolve([]);
            }
        });
    }

    /**
      * Ambil akun berdasarkan nama
      */
    getAccount(accountName, userId = 'default') {
        return new Promise((resolve) => {
            try {
                this.db.get('SELECT * FROM facebook_accounts WHERE user_id = ? AND name = ?', [userId, accountName], (err, account) => {
                    if (err) {
                        console.error('Error getting account:', err);
                        resolve(null);
                        return;
                    }

                    if (!account) {
                        resolve(null);
                        return;
                    }

                    // Decrypt cookie dan format data
                    const formattedAccount = {
                        id: account.id,
                        name: account.name,
                        type: account.type || 'personal',
                        cookie: this.decrypt(account.cookie),
                        pages: account.pages_data ? JSON.parse(account.pages_data) : [],
                        valid: account.is_valid === 1,
                        createdAt: account.created_at,
                        updatedAt: account.updated_at
                    };

                    resolve(formattedAccount);
                });
            } catch (error) {
                console.error('Error getting account:', error);
                resolve(null);
            }
        });
    }

    /**
     * Validasi cookie dan ambil data halaman Facebook
     */
    async validateAccount(accountName, userId = 'default') {
        return new Promise(async (resolve) => {
            try {
                const account = await this.getAccount(accountName, userId);

                if (!account) {
                    resolve({
                        success: false,
                        error: 'Akun tidak ditemukan'
                    });
                    return;
                }

                // Check if account is already valid and recently validated (within 24 hours)
                if (account.valid && account.lastValidated) {
                    const lastValidated = new Date(account.lastValidated);
                    const now = new Date();
                    const hoursSinceValidation = (now - lastValidated) / (1000 * 60 * 60);

                    if (hoursSinceValidation < 24 && account.pages && account.pages.length > 0) {
                        console.log(`Account ${accountName} already valid (validated ${hoursSinceValidation.toFixed(1)} hours ago)`);
                        resolve({
                            success: true,
                            pages: account.pages,
                            message: `Akun ${accountName} sudah valid`,
                            fromCache: true
                        });
                        return;
                    }
                }

                if (!account.cookie) {
                    resolve({
                        success: false,
                        error: 'Cookie tidak ditemukan'
                    });
                    return;
                }

                console.log(`Validating account: ${accountName} (Type: ${account.type})`);

                // Gunakan FacebookAutomation untuk validasi nyata
                const FacebookAutomation = require('./facebook-automation');
                const facebookAutomation = new FacebookAutomation();

                const validationResult = await facebookAutomation.validateCookieAndGetPages(account.cookie, account.type);

                if (validationResult.success) {
                    // Update status akun di database
                    this.db.run(
                        'UPDATE facebook_accounts SET pages_data = ?, is_valid = ?, updated_at = ? WHERE user_id = ? AND name = ?',
                        [JSON.stringify(validationResult.pages), 1, new Date().toISOString(), userId, accountName],
                        (updateErr) => {
                            if (updateErr) {
                                console.error('Error updating account validation:', updateErr);
                            }
                            console.log(`Account ${accountName} validated successfully with ${validationResult.pages.length} pages`);
                            resolve({
                                success: true,
                                pages: validationResult.pages,
                                message: `Akun ${accountName} berhasil divalidasi`,
                                fromCache: false
                            });
                        }
                    );
                } else {
                    // Update status akun sebagai tidak valid
                    this.db.run(
                        'UPDATE facebook_accounts SET pages_data = ?, is_valid = ?, updated_at = ? WHERE user_id = ? AND name = ?',
                        ['[]', 0, new Date().toISOString(), userId, accountName],
                        (updateErr) => {
                            if (updateErr) {
                                console.error('Error updating account validation:', updateErr);
                            }
                            console.log(`Account ${accountName} validation failed: ${validationResult.error}`);
                            resolve({
                                success: false,
                                error: validationResult.error
                            });
                        }
                    );
                }
            } catch (error) {
                console.error('Error validating account:', error);
                resolve({
                    success: false,
                    error: error.message
                });
            }
        });
    }


    /**
     * Test koneksi akun (tanpa menyimpan)
     */
    async testAccount(accountData) {
        try {
            console.log(`Testing account connection for: ${accountData.name} (Type: ${accountData.type})`);

            // Gunakan FacebookAutomation untuk test nyata
            const FacebookAutomation = require('./facebook-automation');
            const facebookAutomation = new FacebookAutomation();

            const validationResult = await facebookAutomation.validateCookieAndGetPages(accountData.cookie, accountData.type);

            console.log(`Test result: ${validationResult.success ? 'SUCCESS' : 'FAILED'}`);

            return {
                success: validationResult.success,
                pages: validationResult.pages || [],
                message: validationResult.message || validationResult.error
            };
        } catch (error) {
            console.error('Error testing account:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Update status validasi akun
     */
    updateAccountValidation(accountName, isValid, pages = [], userId = 'default') {
        return new Promise((resolve) => {
            try {
                this.db.run(
                    'UPDATE facebook_accounts SET pages_data = ?, is_valid = ?, updated_at = ? WHERE user_id = ? AND name = ?',
                    [JSON.stringify(pages), isValid ? 1 : 0, new Date().toISOString(), userId, accountName],
                    function(err) {
                        if (err) {
                            console.error('Error updating account validation:', err);
                            resolve({ success: false, error: err.message });
                            return;
                        }

                        if (this.changes > 0) {
                            resolve({ success: true });
                        } else {
                            resolve({ success: false, error: 'Akun tidak ditemukan' });
                        }
                    }
                );
            } catch (error) {
                console.error('Error updating account validation:', error);
                resolve({ success: false, error: error.message });
            }
        });
    }

    /**
     * Cek apakah ada akun yang valid
     */
    async hasValidAccounts(userId = 'default') {
        const accounts = await this.getAllAccounts(userId);
        return accounts.some(acc => acc.valid);
    }

    /**
     * Ambil akun yang valid saja
     */
    async getValidAccounts(userId = 'default') {
        const accounts = await this.getAllAccounts(userId);
        return accounts.filter(acc => acc.valid);
    }

    /**
     * Bersihkan semua data akun
     */
    clearAllAccounts(userId = 'default') {
        return new Promise((resolve) => {
            try {
                this.db.run('DELETE FROM facebook_accounts WHERE user_id = ?', [userId], function(err) {
                    if (err) {
                        console.error('Error clearing accounts:', err);
                        resolve({ success: false, error: err.message });
                        return;
                    }

                    resolve({
                        success: true,
                        message: `Semua akun berhasil dihapus (${this.changes} akun)`
                    });
                });
            } catch (error) {
                console.error('Error clearing accounts:', error);
                resolve({ success: false, error: error.message });
            }
        });
    }

    /**
     * Export data akun (untuk backup)
     */
    async exportAccounts(userId = 'default') {
        try {
            const accounts = await this.getAllAccounts(userId);
            // Remove sensitive data untuk export
            const exportData = accounts.map(acc => ({
                name: acc.name,
                type: acc.type,
                createdAt: acc.createdAt,
                updatedAt: acc.updatedAt,
                valid: acc.valid,
                pages: acc.pages
            }));

            return {
                success: true,
                data: exportData,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Import data akun (dari backup)
     */
    async importAccounts(importData, userId = 'default') {
        try {
            if (!Array.isArray(importData)) {
                return { success: false, error: 'Format data tidak valid' };
            }

            let imported = 0;
            let skipped = 0;

            for (const importAccount of importData) {
                try {
                    // Check if account exists
                    const existingAccount = await this.getAccount(importAccount.name, userId);

                    if (existingAccount) {
                        // Update existing account (without cookie for security)
                        await new Promise((resolve, reject) => {
                            this.db.run(
                                'UPDATE facebook_accounts SET type = ?, pages_data = ?, is_valid = ?, updated_at = ? WHERE user_id = ? AND name = ?',
                                [
                                    importAccount.type || 'personal',
                                    JSON.stringify(importAccount.pages || []),
                                    importAccount.valid ? 1 : 0,
                                    new Date().toISOString(),
                                    userId,
                                    importAccount.name
                                ],
                                function(err) {
                                    if (err) reject(err);
                                    else resolve();
                                }
                            );
                        });
                        skipped++;
                    } else {
                        // Insert new account (without cookie for security)
                        await new Promise((resolve, reject) => {
                            this.db.run(
                                'INSERT INTO facebook_accounts (user_id, name, type, pages_data, is_valid, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                [
                                    userId,
                                    importAccount.name,
                                    importAccount.type || 'personal',
                                    JSON.stringify(importAccount.pages || []),
                                    importAccount.valid ? 1 : 0,
                                    importAccount.createdAt || new Date().toISOString(),
                                    new Date().toISOString()
                                ],
                                function(err) {
                                    if (err) reject(err);
                                    else resolve();
                                }
                            );
                        });
                        imported++;
                    }
                } catch (error) {
                    console.error(`Error importing account ${importAccount.name}:`, error);
                    skipped++;
                }
            }

            return {
                success: true,
                message: `${imported} akun berhasil diimpor, ${skipped} dilewati`,
                imported: imported,
                skipped: skipped
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Get account statistics
     */
    async getAccountStats(userId = 'default') {
        try {
            const accounts = await this.getAllAccounts(userId);
            const validAccounts = accounts.filter(acc => acc.valid);
            const totalPages = accounts.reduce((total, acc) => total + (acc.pages ? acc.pages.length : 0), 0);

            return {
                total: accounts.length,
                valid: validAccounts.length,
                invalid: accounts.length - validAccounts.length,
                totalPages: totalPages
            };
        } catch (error) {
            console.error('Error getting account stats:', error);
            return {
                total: 0,
                valid: 0,
                invalid: 0,
                totalPages: 0
            };
        }
    }
}

module.exports = AccountManager;
