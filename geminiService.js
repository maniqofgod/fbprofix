const { GoogleGenerativeAI } = require('@google/generative-ai');
const geminiStore = require('./geminiStore');

class GeminiRateLimiter {
    constructor() {
        this.requests = new Map(); // Map untuk menyimpan timestamp requests per user
        this.maxRequests = 10; // Max 10 requests per menit per user
        this.timeWindow = 60 * 1000; // 1 menit dalam milliseconds
    }

    canMakeRequest(userId) {
        const now = Date.now();
        const userRequests = this.requests.get(userId) || [];

        // Hapus requests yang sudah di luar time window
        const validRequests = userRequests.filter(time => now - time < this.timeWindow);

        if (validRequests.length >= this.maxRequests) {
            return false;
        }

        // Tambahkan request baru
        validRequests.push(now);
        this.requests.set(userId, validRequests);

        return true;
    }

    getRemainingTime(userId) {
        const now = Date.now();
        const userRequests = this.requests.get(userId) || [];

        if (userRequests.length < this.maxRequests) {
            return 0;
        }

        const oldestRequest = Math.min(...userRequests);
        return Math.ceil((this.timeWindow - (now - oldestRequest)) / 1000);
    }
}

// API Key Rate Limiter - tracks rate limits per API key
class GeminiApiRateLimiter {
    constructor() {
        this.rateLimitedKeys = new Map(); // Map<apiId, {until: timestamp, reason: string}>
        this.cooldownPeriod = 30 * 60 * 1000; // 30 minutes in milliseconds
    }

    // Check if API key is currently rate limited
    isRateLimited(apiId) {
        const limitInfo = this.rateLimitedKeys.get(apiId);
        if (!limitInfo) return false;

        const now = Date.now();
        if (now >= limitInfo.until) {
            // Cooldown period has expired, remove from rate limited list
            this.rateLimitedKeys.delete(apiId);
            return false;
        }

        return true;
    }

    // Mark API key as rate limited
    markRateLimited(apiId, reason = 'Rate limit exceeded') {
        const until = Date.now() + this.cooldownPeriod;
        this.rateLimitedKeys.set(apiId, {
            until: until,
            reason: reason,
            markedAt: Date.now()
        });
        console.log(`🚫 API Key ${apiId} marked as rate limited until ${new Date(until).toISOString()} (${reason})`);
    }

    // Get remaining cooldown time for an API key
    getRemainingCooldown(apiId) {
        const limitInfo = this.rateLimitedKeys.get(apiId);
        if (!limitInfo) return 0;

        const now = Date.now();
        const remaining = Math.ceil((limitInfo.until - now) / 1000);
        return Math.max(0, remaining);
    }

    // Get all currently rate limited API keys
    getRateLimitedKeys() {
        const now = Date.now();
        const limited = [];

        for (const [apiId, info] of this.rateLimitedKeys.entries()) {
            if (now < info.until) {
                limited.push({
                    apiId,
                    reason: info.reason,
                    remainingSeconds: Math.ceil((info.until - now) / 1000),
                    until: info.until
                });
            } else {
                // Clean up expired entries
                this.rateLimitedKeys.delete(apiId);
            }
        }

        return limited;
    }

    // Clear expired rate limits
    cleanup() {
        const now = Date.now();
        for (const [apiId, info] of this.rateLimitedKeys.entries()) {
            if (now >= info.until) {
                this.rateLimitedKeys.delete(apiId);
            }
        }
    }
}

const rateLimiter = new GeminiRateLimiter();
const apiRateLimiter = new GeminiApiRateLimiter();

class GeminiService {
    async generateContent(fileName, userId = null) { // Removed options parameter
        const startTime = Date.now();
        let apiData = null;
        let success = false;
        let errorMessage = null;
        let usedApiKeys = new Set(); // Track used API keys to avoid infinite loops

        try {
            // Retrieve content settings
            const settings = await geminiStore.getGeminiContentSettings();
            const { contentLanguage, contentModel, customContentPrompt } = settings;

            // Rate limiting check
            if (userId && !rateLimiter.canMakeRequest(userId)) {
                const remainingTime = rateLimiter.getRemainingTime(userId);
                errorMessage = `Rate limit exceeded. Coba lagi dalam ${remainingTime} detik.`;
                throw new Error(errorMessage);
            }

            // Get all available API keys
            const allApis = await geminiStore.getAllApis();
            if (allApis.length === 0) {
                errorMessage = 'Tidak ada API Gemini yang tersedia. Silakan tambahkan API key di panel admin.';
                throw new Error(errorMessage);
            }

            // Try each API key until one works
            let lastError;
            for (const currentApi of allApis) {
                if (usedApiKeys.has(currentApi.id)) continue; // Skip already tried keys

                try {
                    console.log(`🔄 Trying API key: ${currentApi.name} (${currentApi.id})`);
                    apiData = currentApi;

                    const genAI = new GoogleGenerativeAI(apiData.apiKey);

                    // Get model configuration from settings
                    const modelName = contentModel;
                    const availableModels = {
                        'models/gemini-2.0-flash-exp': { name: 'Gemini 2.0 Flash Experimental', description: 'Model terbaru dan paling canggih untuk berbagai tugas', maxTokens: 32768 },
                        'models/gemini-2.0-flash': { name: 'Gemini 2.0 Flash', description: 'Model stabil dan cepat untuk berbagai tugas', maxTokens: 32768 },
                        'models/gemini-pro': { name: 'Gemini Pro Latest', description: 'Model stabil dan andal untuk berbagai tugas', maxTokens: 32768 },
                        'models/gemini-flash-latest': { name: 'Gemini Flash Latest', description: 'Model cepat dan efisien untuk response singkat', maxTokens: 8192 },
                        'models/gemini-1.5-flash': { name: 'Gemini 1.5 Flash', description: 'Model lama yang masih didukung untuk kompatibilitas', maxTokens: 8192 },
                        'models/gemini-1.5-pro': { name: 'Gemini 1.5 Pro', description: 'Model powerful untuk konten yang lebih kompleks', maxTokens: 32768 }
                    };
                    const modelInfo = availableModels[modelName] || availableModels['models/gemini-2.0-flash-exp'];

                    // Get language and prompt template from settings
                    const language = contentLanguage;
                    let prompt;
                    if (customContentPrompt) {
                        prompt = customContentPrompt.replace('${fileName}', fileName);
                    } else {
                        // Default fallback prompt if no custom prompt set
                        const defaultPrompt = `Berdasarkan nama file video: "${fileName}", buat konten YouTube Shorts yang menarik dalam bahasa ${language}.

Format JSON yang harus dikembalikan:
{
   "title": "judul catchy max 100 karakter",
   "description": "deskripsi menarik max 500 karakter",
   "hashtags": "hashtags dipisah koma"
}

Jawab HANYA dengan JSON, tanpa teks lain.`;
                        prompt = defaultPrompt;
                    }

                    const model = genAI.getGenerativeModel({ model: modelName }); // Use modelName from settings

                    // Retry logic dengan exponential backoff
                    let apiError;
                    for (let attempt = 1; attempt <= 3; attempt++) {
                        try {
                            const result = await model.generateContent(prompt);
                            const response = await result.response;
                            const text = response.text();

                            console.log('Raw Gemini response:', text); // Debug log

                            // Parse JSON response dengan validasi lebih baik
                            let content;
                            try {
                                // Coba parse langsung dulu
                                content = JSON.parse(text);
                                console.log('Direct parse successful:', content);
                            } catch (parseError) {
                                console.log('Direct parse failed, trying regex extraction...');
                                console.log('Raw response text:', text);
                                // Jika gagal, coba ekstrak JSON dari teks dengan regex yang lebih robust
                                // Handle markdown code blocks first
                                let cleanText = text;
                                if (text.includes('```json')) {
                                    const jsonBlockMatch = text.match(/```json\s*\n?(\{[\s\S]*?\})\s*\n?```/);
                                    if (jsonBlockMatch) {
                                        cleanText = jsonBlockMatch[1];
                                        console.log('Extracted from json code block:', cleanText);
                                    }
                                } else if (text.includes('```')) {
                                    const codeBlockMatch = text.match(/```\s*\n?(\{[\s\S]*?\})\s*\n?```/);
                                    if (codeBlockMatch) {
                                        cleanText = codeBlockMatch[1];
                                        console.log('Extracted from code block:', cleanText);
                                    }
                                }

                                try {
                                    content = JSON.parse(cleanText);
                                    console.log('Successfully extracted and parsed JSON:', content);
                                } catch (regexError) {
                                    console.log('Regex extraction also failed:', regexError);
                                    // Fallback to original regex
                                    const jsonMatch = cleanText.match(/\{[\s\S]*?\}(?=\s*$|[\r\n]|```)/);
                                    if (!jsonMatch) {
                                        console.log('No JSON found in response. Full text:', text);
                                        throw new Error('Respons tidak valid dari Gemini API - tidak ada format JSON yang benar');
                                    }
                                    content = JSON.parse(jsonMatch[0]);
                                    console.log('Successfully extracted JSON with fallback regex:', content);
                                }
                            }

                            // Validasi hasil
                            if (!content.title && !content.description && !content.hashtags) {
                                throw new Error('Respons kosong dari Gemini API');
                            }

                            success = true;
                            const responseTime = Date.now() - startTime;

                            // Log successful usage
                            if (userId) {
                                await geminiStore.logApiUsage(apiData.id, userId, fileName, success, null, responseTime);
                            }

                            return {
                                title: content.title || fileName,
                                description: content.description || `Video menarik: ${fileName}`,
                                tags: content.hashtags || 'viral,shorts,fyp',
                                generated: true,
                                model: modelName,
                                modelInfo: modelInfo
                            };

                        } catch (error) {
                            apiError = error;
                            console.warn(`Gemini API attempt ${attempt} failed:`, error.message);
                            console.warn('Full error:', error);

                            if (attempt < 3) {
                                const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000); // Exponential backoff max 5s
                                await new Promise(resolve => setTimeout(resolve, delay));
                            }
                        }
                    }

                    // If this API key failed, mark it as used and try the next one
                    usedApiKeys.add(currentApi.id);
                    lastError = apiError;
                    console.log(`❌ API key ${currentApi.name} failed, trying next one...`);

                } catch (error) {
                    // Mark this API as used and continue to next
                    usedApiKeys.add(currentApi.id);
                    lastError = error;
                    console.log(`❌ API key ${currentApi.name} failed with error: ${error.message}`);
                }
            }

            // If all API keys failed, throw the last error
            throw lastError || new Error('Semua API key Gemini gagal digunakan');

        } catch (error) {
            console.error('Error generating content with Gemini:', error);
            errorMessage = error.message;

            // Log error untuk monitoring
            if (userId) {
                console.log(`[GEMINI_ERROR] User ${userId}: ${error.message}`);
            }

            // Fallback jika API gagal
            return {
                title: fileName,
                description: `Video menarik: ${fileName}. Konten ini menggunakan judul default karena AI tidak tersedia sementara.`,
                tags: 'viral,shorts,fyp',
                generated: false,
                error: error.message
            };
        } finally {
            // Log usage even if failed (untuk tracking rate limiting)
            if (!success && userId && apiData) {
                const responseTime = Date.now() - startTime;
                await geminiStore.logApiUsage(apiData.id, userId, fileName, success, errorMessage, responseTime);
            }
        }
    }

    async generateComment(videoTitle, userId = null) { // Removed maxRetries, customPrompt, language from parameters
        const startTime = Date.now();
        let success = false;
        let errorMessage = null;
        let totalAttempts = 0;

        try {
            // Retrieve comment settings
            const settings = await geminiStore.getGeminiCommentSettings();
            const { maxRetries, commentLanguage, commentModel, maxApiUsesPerVideo } = settings;

            // Extract video ID for usage tracking (simple extraction from YouTube URL if present)
            let videoId = videoTitle;
            if (videoTitle.includes('youtube.com') || videoTitle.includes('youtu.be')) {
                const urlMatch = videoTitle.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
                if (urlMatch) {
                    videoId = urlMatch[1];
                }
            }

            // Check if we've exceeded the usage limit for this video
            const usageLimitExceeded = await geminiStore.isVideoUsageLimitExceeded(videoId, maxApiUsesPerVideo);
            if (usageLimitExceeded) {
                console.log(`⏰ Usage limit exceeded for video ${videoId} (${maxApiUsesPerVideo} uses per API). Implementing 5-minute cooldown.`);
                await new Promise(resolve => setTimeout(resolve, 5 * 60 * 1000)); // 5 minutes
                console.log(`✅ Cooldown completed for video ${videoId}`);
            }

            // Rate limiting check
            if (userId && !rateLimiter.canMakeRequest(userId)) {
                const remainingTime = rateLimiter.getRemainingTime(userId);
                errorMessage = `Rate limit exceeded. Coba lagi dalam ${remainingTime} detik.`;
                throw new Error(errorMessage);
            }

            // Get available APIs that haven't reached the limit for this video
            const availableApis = await geminiStore.getAvailableApisForVideo(videoId, maxApiUsesPerVideo);
            if (availableApis.length === 0) {
                errorMessage = `Tidak ada API Gemini yang tersedia untuk video ini. Semua API telah mencapai batas penggunaan (${maxApiUsesPerVideo} kali per API per video).`;
                throw new Error(errorMessage);
            }

            console.log(`🎯 Starting comment generation for: "${videoTitle}" (Video ID: ${videoId})`);
            console.log(`📊 Available APIs: ${availableApis.length}, Max retries: ${maxRetries}, Max uses per API: ${maxApiUsesPerVideo}`);

            // Determine language and get comment settings for templates
            const useLanguage = commentLanguage;
            const commentSettings = await geminiStore.getGeminiCommentSettings();
            const commentPrompts = commentSettings.commentPrompts || {};

            let prompt;
            if (commentPrompts[useLanguage] && commentPrompts[useLanguage].filter(p => p).length > 0) {
                // Pick random non-null template
                const availablePrompts = commentPrompts[useLanguage].filter(p => p);
                const selectedPrompt = availablePrompts[Math.floor(Math.random() * availablePrompts.length)];
                prompt = selectedPrompt.replace('${videoTitle}', videoTitle);
                console.log(`✅ Using language: ${useLanguage}, selected prompt: ${selectedPrompt.substring(0, 60)}...`);
            } else {
                // No templates available - skip commenting
                console.log(`⚠️ No comment templates configured for language: ${useLanguage}`);
                return null;
            }
            console.log(`🤖 Using model: ${commentModel}`);

            // Try up to maxRetries times with available API selection
            for (let retry = 1; retry <= maxRetries; retry++) {
                console.log(`🔄 Comment generation attempt ${retry}/${maxRetries}`);

                // Shuffle available APIs for random selection
                const shuffledApis = [...availableApis].sort(() => Math.random() - 0.5);

                for (const currentApi of shuffledApis) {
                    totalAttempts++;
                    console.log(`🎲 Trying API: ${currentApi.name} (attempt ${totalAttempts})`);

                    try {
                        const genAI = new GoogleGenerativeAI(currentApi.apiKey);
                        const model = genAI.getGenerativeModel({ model: commentModel }); // Use model from settings

                        // Single attempt per API (no internal retries to speed up process)
                        const result = await model.generateContent(prompt);
                        const response = await result.response;
                        const text = response.text().trim();

                        console.log('✅ Raw Gemini comment response:', text);

                        // Validate response
                        if (!text || text.length > 200 || text.length < 2) {
                            console.warn(`⚠️ Invalid response length: ${text.length} characters`);
                            continue; // Try next API
                        }

                        // Increment usage count for this API and video
                        await geminiStore.incrementApiVideoUsage(currentApi.id, videoId);
                        console.log(`📊 Incremented usage count for API ${currentApi.name} on video ${videoId}`);

                        success = true;
                        const responseTime = Date.now() - startTime;

                        // Log successful usage
                        if (userId) {
                            await geminiStore.logApiUsage(currentApi.id, userId, videoTitle, success, null, responseTime);
                        }

                        console.log(`🎉 Comment generated successfully with API: ${currentApi.name}`);
                        console.log(`💬 Generated comment: "${text}"`);

                        return text;

                    } catch (error) {
                        console.warn(`❌ API ${currentApi.name} failed:`, error.message);

                        // Log failed attempt
                        if (userId) {
                            const responseTime = Date.now() - startTime;
                            await geminiStore.logApiUsage(currentApi.id, userId, videoTitle, false, error.message, responseTime);
                        }

                        // Continue to next API
                        continue;
                    }
                }

                // If we've tried all available APIs in this retry round, wait a bit before next round
                if (retry < maxRetries) {
                    const waitTime = Math.min(1000 * retry, 3000); // Progressive wait: 1s, 2s, 3s
                    console.log(`⏳ All available APIs tried in round ${retry}, waiting ${waitTime}ms before next round...`);
                    await new Promise(resolve => setTimeout(resolve, waitTime));
                }
            }

            // If we get here, all attempts failed
            errorMessage = `Failed to generate comment after ${totalAttempts} attempts with ${availableApis.length} available APIs`;
            console.error(`💥 ${errorMessage}`);
            throw new Error(errorMessage);

        } catch (error) {
            console.error('🚨 Error generating comment with Gemini:', error);
            errorMessage = error.message;

            // Log final error
            if (userId) {
                console.log(`[GEMINI_COMMENT_ERROR] User ${userId}: ${error.message} (after ${totalAttempts} attempts)`);
            }

            // Return null to indicate failure (no fallback comment)
            return null;
        }
    }

    async validateApiKey(apiKey) {
        try {
            // Basic format validation first
            if (!apiKey || typeof apiKey !== 'string' || apiKey.length < 20) {
                console.log('API key format invalid - too short or not a string');
                return false;
            }

            // Try to make a minimal API call to test validity
            const genAI = new GoogleGenerativeAI(apiKey);
            const model = genAI.getGenerativeModel({ model: 'models/gemini-2.0-flash-exp' });

            // Use the cheapest possible prompt to test connectivity
            const result = await model.generateContent('OK');
            const response = await result.response;
            const text = response.text();

            // If we get any response, the API key works
            if (text && text.trim().length > 0) {
                console.log('API key validation successful');
                return true;
            }

            return false;
        } catch (error) {
            console.error('Error validating Gemini API key:', error);

            // If it's a quota/rate limit/429 error, treat as valid
            // This allows API keys to be added even when temporarily quota-limited
            const isQuotaError = error.message?.toLowerCase().includes('quota') ||
                               error.message?.toLowerCase().includes('rate limit') ||
                               error.message?.toLowerCase().includes('resource exhausted') ||
                               error.status === 429;

            if (isQuotaError) {
                console.log('Quota error detected - allowing API key save despite temporary quota limit');
                return true; // Allow it through - the key is valid, just quota-limited
            }

            // For other errors (invalid key format, auth errors, etc.), reject
            return false;
        }
    }

    // Get currently rate limited API keys
    getRateLimitedKeys() {
        return apiRateLimiter.getRateLimitedKeys();
    }

    // Check if a specific API key is rate limited
    isApiKeyRateLimited(apiId) {
        return apiRateLimiter.isRateLimited(apiId);
    }

    // Get remaining cooldown time for an API key
    getApiKeyCooldown(apiId) {
        return apiRateLimiter.getRemainingCooldown(apiId);
    }
}

module.exports = new GeminiService();
