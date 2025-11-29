const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Database path constant for backwards compatibility
const DB_PATH = path.join(__dirname, 'reelsync.db');

// Helper function to ensure database connection
function ensureDatabase() {
    return new Promise((resolve, reject) => {
        // For now, just resolve since GeminiStore handles its own database
        resolve();
    });
}

class GeminiPromptManager {
    static getPromptTemplates() {
        return {
            default: `Berdasarkan nama file video: "{fileName}", buat konten YouTube Shorts yang menarik dengan format JSON berikut:
{
    "title": "judul yang catchy dan menarik (max 100 karakter)",
    "description": "deskripsi menarik yang menggambarkan konten video (max 500 karakter)",
    "hashtags": "beberapa hashtag relevan dipisah dengan koma"
}

Pastikan:
- Judul catchy dan mengundang klik
- Deskripsi informatif tapi singkat
- Hashtag maksimal 10, relevan dengan konten
- Gunakan bahasa Indonesia yang natural
- Sesuaikan dengan konten dari nama file

Jika nama file dalam bahasa Inggris, tetap gunakan bahasa Indonesia untuk output.`,

            detailed: `Berdasarkan nama file video: "{fileName}", buat konten YouTube yang sangat detail dan engaging dengan format JSON berikut:
{
    "title": "judul yang sangat menarik dan SEO-friendly (max 100 karakter)",
    "description": "deskripsi lengkap dan menarik yang menggambarkan konten video dengan detail (max 5000 karakter)",
    "hashtags": "10-15 hashtag yang sangat relevan dan trending, dipisah dengan koma"
}

Persyaratan khusus:
- Judul harus mengandung kata kunci utama dari nama file
- Deskripsi harus mencakup: pengantar menarik, deskripsi konten, call-to-action, dan kata kunci terkait
- Hashtag harus mencakup: kata kunci utama, kata kunci terkait, trending topics, dan brand hashtags
- Gunakan bahasa Indonesia yang profesional dan engaging
- Optimasi untuk algoritma YouTube dan SEO

Jika nama file dalam bahasa Inggris, tetap gunakan bahasa Indonesia untuk output.`,

            short_form: `Berdasarkan nama file video: "{fileName}", buat konten YouTube Shorts/ TikTok yang super catchy dengan format JSON berikut:
{
    "title": "judul pendek yang sangat menarik dan viral (max 60 karakter)",
    "description": "deskripsi super singkat tapi bikin penasaran (max 200 karakter)",
    "hashtags": "5-8 hashtag yang sedang trending untuk Shorts/TikTok, dipisah dengan koma"
}

Fokus pada:
- Judul harus sangat catchy dan memancing klik
- Deskripsi harus membuat orang langsung ingin nonton
- Hashtag harus yang lagi trending di platform Shorts/TikTok
- Gunakan bahasa Indonesia gaul yang kekinian
- Buat konten yang relatable dan shareable

Jika nama file dalam bahasa Inggris, tetap gunakan bahasa Indonesia untuk output.`,

            educational: `Berdasarkan nama file video: "{fileName}", buat konten edukasi yang informatif dengan format JSON berikut:
{
    "title": "judul edukatif yang jelas dan menarik (max 100 karakter)",
    "description": "penjelasan detail tentang konten edukasi (max 1000 karakter)",
    "hashtags": "hashtag edukasi dan pembelajaran yang relevan, dipisah dengan koma"
}

Buat konten yang:
- Judul harus langsung menjelaskan manfaat yang didapat pemirsa
- Deskripsi harus mencakup: apa yang akan dipelajari, siapa target audience, dan manfaat praktis
- Sertakan call-to-action untuk like, comment, dan subscribe
- Gunakan bahasa Indonesia yang mudah dipahami semua kalangan
- Tambahkan nilai edukasi yang tinggi

Jika nama file dalam bahasa Inggris, tetap gunakan bahasa Indonesia untuk output.`
        };
    }

    static getPrompt(template = 'default', fileName) {
        const templates = this.getPromptTemplates();
        return templates[template]?.replace('{fileName}', fileName) || templates.default.replace('{fileName}', fileName);
    }
}

class GeminiModelManager {
    static getAvailableModels() {
        return {
            'gemini-1.5-flash': {
                name: 'Gemini 1.5 Flash',
                description: 'Model cepat dan efisien untuk response singkat',
                maxTokens: 8192
            },
            'gemini-1.5-pro': {
                name: 'Gemini 1.5 Pro',
                description: 'Model powerful untuk konten yang lebih kompleks',
                maxTokens: 32768
            }
        };
    }

    static getModel(modelName = 'gemini-1.5-flash') {
        const models = this.getAvailableModels();
        return models[modelName] || models['gemini-1.5-flash'];
    }
}

// Export helper classes untuk digunakan di routes
class GeminiStore {
    constructor() {
        this.dbPath = path.join(__dirname, 'reelsync.db');
        this.db = null;
        this.initDatabase();
    }

    async initDatabase() {
        return new Promise((resolve, reject) => {
            this.db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    console.error('Error opening GeminiStore database:', err.message);
                    reject(err);
                    return;
                }

                // Create tables
                const createTables = `
                    CREATE TABLE IF NOT EXISTS gemini_apis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        api_key TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_valid BOOLEAN DEFAULT 1,
                        last_used DATETIME,
                        usage_count INTEGER DEFAULT 0,
                        user_id INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    );

                    CREATE TABLE IF NOT EXISTS gemini_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_id INTEGER,
                        user_id INTEGER,
                        file_name TEXT,
                        success BOOLEAN,
                        error_message TEXT,
                        response_time INTEGER,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (api_id) REFERENCES gemini_apis(id),
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    );

                    CREATE TABLE IF NOT EXISTS gemini_settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT UNIQUE NOT NULL,
                        value TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS api_video_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        api_id INTEGER NOT NULL,
                        video_id TEXT NOT NULL,
                        usage_count INTEGER DEFAULT 0,
                        last_used DATETIME,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (api_id) REFERENCES gemini_apis(id),
                        UNIQUE(api_id, video_id)
                    );

                    INSERT OR IGNORE INTO gemini_settings (key, value) VALUES ('geminiCommentSettings', '{"maxRetries":5,"commentLanguage":"indonesia","commentModel":"models/gemini-2.0-flash","maxApiUsesPerVideo":2,"customCommentPrompt":null}');
                    INSERT OR IGNORE INTO gemini_settings (key, value) VALUES ('geminiContentSettings', '{"contentLanguage":"indonesia","contentModel":"models/gemini-2.0-flash","customContentPrompt":null}');
                `;

                this.db.exec(createTables, (err) => {
                    if (err) {
                        console.error('Error creating GeminiStore tables:', err.message);
                        reject(err);
                        return;
                    }
                    console.log('✅ GeminiStore database initialized');
                    resolve();
                });
            });
        });
    }

    async getAllApis(userId) {
        return new Promise((resolve, reject) => {
            const query = userId ? 'SELECT * FROM gemini_apis WHERE user_id = ?' : 'SELECT * FROM gemini_apis';
            const params = userId ? [userId] : [];

            this.db.all(query, params, (err, rows) => {
                if (err) {
                    console.error('Error reading Gemini APIs:', err);
                    resolve([]);
                    return;
                }

                const apis = rows.map(row => ({
                    id: row.id,
                    name: row.name,
                    apiKey: row.api_key,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                    isValid: row.is_valid === 1,
                    lastUsed: row.last_used,
                    usageCount: row.usage_count,
                    userId: row.user_id
                }));

                resolve(apis);
            });
        });
    }

    async addApi(apiKey, name = null, userId = null, id = null) {
        return new Promise((resolve, reject) => {
            if (id) {
                // Update existing API
                const updateQuery = apiKey && apiKey !== 'existing'
                    ? 'UPDATE gemini_apis SET name = ?, api_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?'
                    : 'UPDATE gemini_apis SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?';

                const params = apiKey && apiKey !== 'existing'
                    ? [name, apiKey, id, userId]
                    : [name, id, userId];

                this.db.run(updateQuery, params, function(err) {
                    if (err) {
                        console.error('Error updating Gemini API:', err);
                        reject(err);
                        return;
                    }

                    if (this.changes > 0) {
                        // Return updated API data
                        const newApi = {
                            id: id,
                            name: name,
                            apiKey: apiKey && apiKey !== 'existing' ? apiKey : undefined,
                            updatedAt: new Date().toISOString(),
                            userId: userId
                        };
                        resolve(newApi);
                    } else {
                        reject(new Error('API not found'));
                    }
                });
            } else {
                // Add new API
                const insertQuery = 'INSERT INTO gemini_apis (name, api_key, user_id) VALUES (?, ?, ?)';
                const apiName = name || `API Key ${(new Date()).getTime()}`;

                this.db.run(insertQuery, [apiName, apiKey, userId], function(err) {
                    if (err) {
                        console.error('Error adding Gemini API:', err);
                        reject(err);
                        return;
                    }

                    const newApi = {
                        id: this.lastID,
                        name: apiName,
                        apiKey: apiKey,
                        createdAt: new Date().toISOString(),
                        isValid: true,
                        lastUsed: null,
                        usageCount: 0,
                        userId: userId
                    };

                    resolve(newApi);
                });
            }
        });
    }

    async deleteApi(id, userId) {
        return new Promise((resolve, reject) => {
            this.db.run('DELETE FROM gemini_apis WHERE id = ? AND user_id = ?', [id, userId], function(err) {
                if (err) {
                    console.error('Error deleting Gemini API:', err);
                    reject(err);
                    return;
                }
                resolve(this.changes > 0);
            });
        });
    }

    async getApiById(id, userId) {
        return new Promise((resolve, reject) => {
            this.db.get('SELECT * FROM gemini_apis WHERE id = ? AND user_id = ?', [id, userId], (err, row) => {
                if (err) {
                    console.error('Error getting Gemini API by ID:', err);
                    resolve(null);
                    return;
                }

                if (!row) {
                    resolve(null);
                    return;
                }

                resolve({
                    id: row.id,
                    name: row.name,
                    apiKey: row.api_key,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                    isValid: row.is_valid === 1,
                    lastUsed: row.last_used,
                    usageCount: row.usage_count,
                    userId: row.user_id
                });
            });
        });
    }

    async getRandomApi(userId) {
        return new Promise((resolve, reject) => {
            this.db.all('SELECT * FROM gemini_apis WHERE user_id = ? AND is_valid = 1', [userId], (err, rows) => {
                if (err) {
                    console.error('Error getting Gemini APIs:', err);
                    resolve(null);
                    return;
                }

                if (rows.length === 0) {
                    resolve(null);
                    return;
                }

                const randomIndex = Math.floor(Math.random() * rows.length);
                const row = rows[randomIndex];

                resolve({
                    id: row.id,
                    name: row.name,
                    apiKey: row.api_key,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at,
                    isValid: row.is_valid === 1,
                    lastUsed: row.last_used,
                    usageCount: row.usage_count,
                    userId: row.user_id
                });
            });
        });
    }

    async logApiUsage(apiId, userId, fileName, success, errorMessage = null, responseTime = null) {
        try {
            await ensureDatabase();
            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                // Check if we need to remove old records to keep under 1000
                db.get('SELECT COUNT(*) as count FROM gemini_usage', [], (err, row) => {
                    if (err) {
                        db.close();
                        reject(err);
                        return;
                    }

                    if (row.count >= 1000) {
                        // Remove oldest records leaving 900
                        db.run('DELETE FROM gemini_usage WHERE id IN (SELECT id FROM gemini_usage ORDER BY timestamp DESC LIMIT -1 OFFSET 900)', [], (err) => {
                            if (err) {
                                console.error('Error cleaning up old usage logs:', err);
                            }
                        });
                    }

                    // Insert new log
                    db.run('INSERT INTO gemini_usage (id, api_id, user_id, file_name, success, error_message, response_time, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           [Date.now(), apiId, userId, fileName, success ? 1 : 0, errorMessage, responseTime, new Date().toISOString()], function(err) {
                        db.close();
                        if (err) {
                            console.error('Error logging API usage:', err);
                            reject(err);
                        } else {
                            resolve();
                        }
                    });
                });
            });
        } catch (error) {
            console.error('Error logging Gemini API usage:', error);
        }
    }

    async getGeminiCommentSettings() {
        try {
            return new Promise((resolve, reject) => {
                this.db.get('SELECT value FROM gemini_settings WHERE key = ?', ['geminiCommentSettings'], (err, row) => {
                    if (err) {
                        console.error('Error reading Gemini comment settings:', err);
                        reject(err);
                    } else if (row && row.value) {
                        const settings = JSON.parse(row.value);
                        // Ensure commentPrompts exist with default templates if not present for ALL languages
                        if (!settings.commentPrompts) {
                            settings.commentPrompts = {};
                        }

                        const defaultPrompts = this.getDefaultCommentPrompts();
                        const languages = ['indonesia', 'english', 'sunda', 'mandarin'];

                        // Merge existing templates with defaults for missing languages
                        languages.forEach(lang => {
                            if (!settings.commentPrompts[lang] || !Array.isArray(settings.commentPrompts[lang]) || settings.commentPrompts[lang].filter(p => p).length === 0) {
                                console.log(`📝 Adding default templates for missing language: ${lang}`);
                                settings.commentPrompts[lang] = defaultPrompts[lang];
                            }
                        });

                        // If we added any defaults, save them back to database (but don't fail if this fails)
                        if (Object.keys(settings.commentPrompts).length > 0) {
                            this.setGeminiCommentSettings(settings).catch(console.warn);
                        }

                        resolve(settings);
                    } else {
                        // Should not happen since we insert defaults, but fallback with default prompts
                        const defaultSettings = {
                            maxRetries: 5,
                            commentLanguage: 'indonesia',
                            commentModel: 'models/gemini-2.0-flash',
                            maxRetries: 5,
                            maxApiUsesPerVideo: 2,
                            customCommentPrompt: null,
                            commentPrompts: this.getDefaultCommentPrompts()
                        };
                        resolve(defaultSettings);
                    }
                });
            });
        } catch (error) {
            console.error('Error reading Gemini comment settings:', error);
            return {
                maxRetries: 5,
                commentLanguage: 'indonesia',
                commentModel: 'models/gemini-2.0-flash',
                maxRetries: 5,
                maxApiUsesPerVideo: 2,
                customCommentPrompt: null,
                commentPrompts: this.getDefaultCommentPrompts()
            };
        }
    }

    async setGeminiCommentSettings(settings) {
        try {
            return new Promise((resolve, reject) => {
                this.db.run('UPDATE gemini_settings SET value = ? WHERE key = ?',
                           [JSON.stringify(settings), 'geminiCommentSettings'], function(err) {
                    if (err) {
                        console.error('Error setting Gemini comment settings:', err);
                        reject(err);
                    } else {
                        resolve(settings);
                    }
                });
            });
        } catch (error) {
            console.error('Error setting Gemini comment settings:', error);
            throw error;
        }
    }

    async getGeminiContentSettings() {
        try {
            await ensureDatabase();
            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                db.get('SELECT value FROM gemini_settings WHERE key = ?', ['geminiContentSettings'], (err, row) => {
                    db.close();
                    if (err) {
                        console.error('Error reading Gemini content settings:', err);
                        reject(err);
                    } else if (row && row.value) {
                        resolve(JSON.parse(row.value));
                    } else {
                        // Should not happen since we insert defaults, but fallback
                        resolve({
                            contentLanguage: 'indonesia',
                            contentModel: 'models/gemini-2.0-flash',
                            customContentPrompt: null
                        });
                    }
                });
            });
        } catch (error) {
            console.error('Error reading Gemini content settings:', error);
            return {
                contentLanguage: 'indonesia',
                contentModel: 'models/gemini-2.0-flash',
                customContentPrompt: null
            };
        }
    }

    async setGeminiContentSettings(settings) {
        try {
            await ensureDatabase();
            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                db.run('UPDATE gemini_settings SET value = ? WHERE key = ?',
                       [JSON.stringify(settings), 'geminiContentSettings'], function(err) {
                    db.close();
                    if (err) {
                        console.error('Error setting Gemini content settings:', err);
                        reject(err);
                    } else {
                        resolve(settings);
                    }
                });
            });
        } catch (error) {
            console.error('Error setting Gemini content settings:', error);
            throw error;
        }
    }

    async getUsageStats() {
        try {
            await ensureDatabase();
            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                // Get overall stats
                db.all(`
                    SELECT
                        COUNT(*) as total_requests,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful_requests,
                        AVG(response_time) as avg_response_time
                    FROM gemini_usage
                `, [], (err, overallStats) => {
                    if (err) {
                        db.close();
                        console.error('Error getting overall usage stats:', err);
                        reject(err);
                        return;
                    }

                    // Get last 24h stats
                    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
                    db.all(`
                        SELECT
                            COUNT(*) as recent_requests,
                            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as recent_successful
                        FROM gemini_usage
                        WHERE timestamp >= ?
                    `, [yesterday], (err, recentStats) => {
                        db.close();
                        if (err) {
                            console.error('Error getting recent usage stats:', err);
                            reject(err);
                            return;
                        }

                        const total = overallStats[0].total_requests || 0;
                        const successful = overallStats[0].successful_requests || 0;
                        const failed = total - successful;
                        const successRate = total > 0 ? ((successful / total) * 100).toFixed(2) : '0.00';

                        const recentTotal = recentStats[0].recent_requests || 0;
                        const recentSuccessful = recentStats[0].recent_successful || 0;
                        const recentSuccessRate = recentTotal > 0 ? ((recentSuccessful / recentTotal) * 100).toFixed(2) : '0.00';
                        const avgResponseTime = overallStats[0].avg_response_time ?
                            Math.round(overallStats[0].avg_response_time) : 0;

                        resolve({
                            totalRequests: total,
                            successfulRequests: successful,
                            failedRequests: failed,
                            successRate: `${successRate}%`,
                            recentRequests: recentTotal,
                            recentSuccessRate: `${recentSuccessRate}%`,
                            averageResponseTime: avgResponseTime
                        });
                    });
                });
            });
        } catch (error) {
            console.error('Error getting usage stats:', error);
            return null;
        }
    }

    // API Video Usage tracking methods
    async getApiVideoUsage(apiId, videoId) {
        try {
            await ensureDatabase();
            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                db.get('SELECT * FROM api_video_usage WHERE api_id = ? AND video_id = ?', [apiId, videoId], (err, row) => {
                    db.close();
                    if (err) {
                        console.error('Error reading API video usage:', err);
                        reject(err);
                    } else {
                        resolve(row || { api_id: apiId, video_id: videoId, usage_count: 0, last_used: null });
                    }
                });
            });
        } catch (error) {
            console.error('Error getting API video usage:', error);
            return { api_id: apiId, video_id: videoId, usage_count: 0, last_used: null };
        }
    }

    async incrementApiVideoUsage(apiId, videoId) {
        try {
            await ensureDatabase();
            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                const now = new Date().toISOString();
                db.run(`INSERT OR REPLACE INTO api_video_usage (api_id, video_id, usage_count, last_used, updated_at)
                       VALUES (?, ?,
                              COALESCE((SELECT usage_count + 1 FROM api_video_usage WHERE api_id = ? AND video_id = ?), 1),
                              ?, ?)`,
                       [apiId, videoId, apiId, videoId, now, now], function(err) {
                    db.close();
                    if (err) {
                        console.error('Error incrementing API video usage:', err);
                        reject(err);
                    } else {
                        resolve(this.changes > 0);
                    }
                });
            });
        } catch (error) {
            console.error('Error incrementing API video usage:', error);
            throw error;
        }
    }

    async getAvailableApisForVideo(videoId, maxUsesPerVideo) {
        try {
            await ensureDatabase();
            const allApis = await this.getAllApis();
            if (allApis.length === 0) return [];

            return new Promise((resolve, reject) => {
                const db = new sqlite3.Database(DB_PATH);
                const apiIds = allApis.map(api => api.id);

                // Get usage counts for all APIs for this video
                const placeholders = apiIds.map(() => '?').join(',');
                db.all(`SELECT api_id, usage_count FROM api_video_usage WHERE api_id IN (${placeholders}) AND video_id = ?`,
                       [...apiIds, videoId], (err, rows) => {
                    db.close();
                    if (err) {
                        console.error('Error getting API video usage for all APIs:', err);
                        reject(err);
                        return;
                    }

                    // Create a map of api_id to usage count
                    const usageMap = {};
                    rows.forEach(row => {
                        usageMap[row.api_id] = row.usage_count || 0;
                    });

                    // Filter APIs that haven't reached the limit
                    const availableApis = allApis.filter(api =>
                        (usageMap[api.id] || 0) < maxUsesPerVideo
                    );

                    resolve(availableApis);
                });
            });
        } catch (error) {
            console.error('Error getting available APIs for video:', error);
            return [];
        }
    }

    async isVideoUsageLimitExceeded(videoId, maxUsesPerVideo) {
        try {
            const availableApis = await this.getAvailableApisForVideo(videoId, maxUsesPerVideo);
            return availableApis.length === 0;
        } catch (error) {
            console.error('Error checking if video usage limit exceeded:', error);
            return true; // Assume exceeded if error
        }
    }

    getDefaultCommentPrompts() {
        return {
            indonesia: [
                'Video YouTube dengan judul: "${videoTitle}". Buat komentar natural dalam BAHASA INDONESIA saja. Maksimal 150 karakter. HANYA berikan komentar tekstual, TIDAK ada penjelasan atau teks tambahan apapun.',
                'Dengan tidak memperdulikan bahasa judul video, buat komentar dalam BAHASA INDONESIA untuk video: "${videoTitle}". Maks 150 karakter. Jawab HANYA dengan komentar Indonesia.',
                'Komentar YouTube yang natural dan autentik dalam BAHASA INDONESIA untuk video berjudul: "${videoTitle}". Maksimal 150 karakter. Output HANYA komentar tekstual tanpa bahasa lain.',
                'Video: "${videoTitle}". Mustahil bahasa komentar bukan BAHASA INDONESIA. Buat komentar maks 150 karakter dalam bahasa Indonesia saja. HANYA komentar, tidak ada yang lain.'
            ],
            english: [
                'YouTube video titled: "${videoTitle}". Create a natural, authentic viewer comment EXCLUSIVELY in ENGLISH language only. Max 150 characters. Respond ONLY with the English comment text.',
                'Regardless of the video title language, create a comment in ENGLISH ONLY for video: "${videoTitle}". Maximum 150 characters. Respond with ONLY the English comment.',
                'Generate a natural English comment for YouTube video titled: "${videoTitle}". Absolutely NO languages other than ENGLISH. Max 150 characters. Output ONLY the English comment.',
                'Video: "${videoTitle}". Comment MUST be in ENGLISH language exclusively. Create natural viewer comment in English, max 150 characters. Respond with ONLY the English comment text.'
            ],
            sunda: [
                'Video YouTube judulna: "${videoTitle}". Jieun komentar alami dina BASA SUNDA wungkul. Maksimal 120 karakter. Wangsul ku komentar Sundana wungkul, teu aya basa séjén.',
                'Teu paduli basa judul video, jieun komentar BASA SUNDA pikeun video: "${videoTitle}". Maks 120 karakter. Wangsul ku komentar Sundana wungkul.',
                'Komentar YouTube anu natural dina BASE SUNDA pikeun video judul: "${videoTitle}". Maksimal 120 karakter. Hasilkeun ukur komentar basa Sunda, teu aya basa lian.',
                'Video: "${videoTitle}". Komentar KUDU BASA SUNDA wungkul. Jieun komentar alami maks 120 karakter basa Sunda. Hasilkeun ukur komentar Sunda.'
            ],
            mandarin: [
                'YouTube视频标题:"${videoTitle}"。创建一个自然的、真实的观众评论，完全只用中文书写。最大150字符。只回复评论中文文字。',
                '无论视频标题语言如何，创作完全用中文的评论，针对视频:"${videoTitle}"。最大150字符。只回复中文评论。',
                '为标题为:"${videoTitle}"的YouTube视频生成自然中文评论。绝对只用中文书写。最大150字符。只输出中文评论文字。',
                '视频:"${videoTitle}"。评论必须完全只用中文书写。创建自然的中文字幕评论，最大150字符。只回复中文评论内容。'
            ]
        };
    }

    setDbPath(newPath) {
        DB_PATH = newPath;
    }
}

// Export helper classes untuk digunakan di routes
module.exports.GeminiModelManager = GeminiModelManager;

// Initialize migration on module load
// migrateFromJson().catch(console.error);

module.exports = new GeminiStore();
