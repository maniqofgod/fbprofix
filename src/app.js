// Application State
let appState = {
    accounts: [],
    currentAccount: null,
    uploadQueue: [],
    settings: {
        uploadDelay: 30000,
        maxRetries: 3,
        autoStartQueue: false,
        showNotifications: true,
        showBrowser: false
    },
    logs: [],
    geminiApis: [],
    user: null,
    isAuthenticated: false
};

// API Base URL
const API_BASE = window.location.origin;

// DOM Elements
let elements = {};

// Current user info
let currentUser = null;

// Analytics state
let analyticsState = {
    currentTimeRange: '30d',
    currentUserFilter: '',
    dashboardData: null,
    isLoading: false
};

// Admin state
let adminState = {
    users: [],
    isLoading: false,
    currentEditingUser: null
};

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
    initializeElements();
    setupEventListeners();

    // Check authentication status first
    await checkAuthStatus();

    // Load app data only if authenticated
    if (appState.isAuthenticated) {
        await loadAppData();
        setupNavigation();
        updateStatusBar();
    }
});

// Check authentication status on page load
async function checkAuthStatus() {
    try {
        const response = await fetch(`${API_BASE}/auth/check`);

        if (response.ok) {
            const result = await response.json();
            if (result.authenticated) {
                appState.user = result.user;
                appState.isAuthenticated = true;
                showApp();
                updateUserInfo();
                showToast(`Selamat datang kembali, ${result.user.displayName || result.user.username}!`, 'success');
            } else {
                showLogin();
                updateUserInfo();
            }
        } else {
            // If auth check fails, assume not authenticated
            showLogin();
            updateUserInfo();
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        showLogin();
    }
}

// Show login form and hide app
function showLogin() {
    const loginOverlay = document.getElementById('login-overlay');
    const appContainer = document.getElementById('app-container');

    if (loginOverlay) {
        loginOverlay.style.display = 'flex';
    }
    if (appContainer) {
        appContainer.style.display = 'none';
    }
}

// Show app and hide login form
function showApp() {
    const loginOverlay = document.getElementById('login-overlay');
    const appContainer = document.getElementById('app-container');

    if (loginOverlay) {
        loginOverlay.style.display = 'none';
    }
    if (appContainer) {
        appContainer.style.display = 'block';
    }
}

// Initialize DOM elements
function initializeElements() {
    elements = {
        // Navigation
        navTabs: document.querySelectorAll('.nav-tab'),
        tabPanes: document.querySelectorAll('.tab-pane'),

        // Account Management
        accountsList: document.getElementById('accounts-list'),
        addAccountBtn: document.getElementById('add-account-btn'),
        accountModal: document.getElementById('account-modal'),
        accountForm: document.getElementById('account-form'),
        accountName: document.getElementById('account-name'),
        accountType: document.getElementById('account-type'),
        accountCookie: document.getElementById('account-cookie'),
        testCookieBtn: document.getElementById('test-cookie-btn'),
        saveAccountBtn: document.getElementById('save-account-btn'),
        cancelAccountBtn: document.getElementById('cancel-account-btn'),
        modalClose: document.getElementById('modal-close'),

        // Admin Accounts
        adminAccountsList: document.getElementById('admin-accounts-list'),
        totalAccounts: document.getElementById('total-accounts'),

        // Upload Form
        uploadForm: document.getElementById('upload-form'),
        accountSelect: document.getElementById('account-select'),
        pageSelect: document.getElementById('page-select'),
        uploadMode: document.querySelectorAll('input[name="upload-mode"]'),
        uploadType: document.querySelectorAll('input[name="upload-type"]'),
        videoFile: document.getElementById('video-file'),
        selectFileBtn: document.getElementById('select-file-btn'),
        caption: document.getElementById('caption'),
        scheduleTime: document.getElementById('schedule-time'),
        addToQueueBtn: document.getElementById('add-to-queue-btn'),

        // Bulk Upload Elements
        bulkFiles: document.getElementById('bulk-files'),
        selectBulkFilesBtn: document.getElementById('select-bulk-files-btn'),
        bulkFilesList: document.getElementById('bulk-files-list'),
        bulkCaptionLanguage: document.getElementById('bulk-caption-language'),
        bulkInterval: document.getElementById('bulk-interval'),
        bulkStartTime: document.getElementById('bulk-start-time'),
        bulkGenerateCaptionsBtn: document.getElementById('bulk-generate-captions-btn'),

        // Queue Management
        queueFilter: document.getElementById('user-filter'),
        queueUserSelect: document.getElementById('queue-user-select'),
        queueList: document.getElementById('queue-list'),
        refreshQueueBtn: document.getElementById('refresh-queue-btn'),
        pendingCount: document.getElementById('pending-count'),
        processingCount: document.getElementById('processing-count'),
        completedCount: document.getElementById('completed-count'),
        failedCount: document.getElementById('failed-count'),

        // Settings
        settingsForm: document.getElementById('settings-form'),
        uploadDelay: document.getElementById('upload-delay'),
        maxRetries: document.getElementById('max-retries'),
        autoStartQueue: document.getElementById('auto-start-queue'),
        showNotifications: document.getElementById('show-notifications'),
        showBrowser: document.getElementById('show-browser'),
        resetSettingsBtn: document.getElementById('reset-settings-btn'),

        // Logs
        logsContainer: document.getElementById('logs-container'),
        clearLogsBtn: document.getElementById('clear-logs-btn'),
        exportLogsBtn: document.getElementById('export-logs-btn'),

    // Debug Tab Elements
    refreshScreenshotsBtn: document.getElementById('refresh-screenshots-btn'),
    clearTerminalLogsBtn: document.getElementById('clear-terminal-logs-btn'),
    terminalMonitor: document.getElementById('terminal-monitor'),
    terminalOutput: document.getElementById('terminal-output'),
    screenshotsGallery: document.getElementById('screenshots-gallery'),

    // Login Elements
    loginOverlay: document.getElementById('login-overlay'),
    loginForm: document.getElementById('login-form'),
    registerBtn: document.getElementById('register-btn'),
    loginBtn: document.getElementById('login-btn'),
    loginTabBtn: document.querySelector('.tab[data-tab="login"]'),
    registerTabBtn: document.querySelector('.tab[data-tab="register"]'),
    loginTab: document.getElementById('login-tab'),
    registerTab: document.getElementById('register-tab'),
    loginUsername: document.getElementById('login-username'),
    loginPassword: document.getElementById('login-password'),
    registerUsername: document.getElementById('register-username'),
    registerPassword: document.getElementById('register-password'),
    registerPasswordConfirm: document.getElementById('register-password-confirm'),
    registerDisplayName: document.getElementById('register-display-name'),
    loginMessage: document.getElementById('login-message'),

    // Header/User Info Elements
    logoutBtn: document.getElementById('logout-btn'),
    userInfo: document.getElementById('user-info'),
    userDisplayName: document.getElementById('user-display-name'),

    // Change Password Elements
    changePasswordForm: document.getElementById('change-password-form'),
    currentPassword: document.getElementById('current-password'),
    newPassword: document.getElementById('new-password'),
    confirmNewPassword: document.getElementById('confirm-new-password'),

        // Status
        statusText: document.getElementById('status-text'),
        queueStatus: document.querySelector('#queue-status'),

        // Gemini AI Caption
        captionLanguage: document.getElementById('caption-language'),
        generateCaptionBtn: document.getElementById('generate-caption-btn'),
        geminiModal: document.getElementById('gemini-modal'),
        geminiForm: document.getElementById('gemini-form'),
        geminiApiName: document.getElementById('gemini-api-name'),
        geminiApiKey: document.getElementById('gemini-api-key'),
        testGeminiApiBtn: document.getElementById('test-gemini-api-btn'),
        saveGeminiBtn: document.getElementById('save-gemini-btn'),
        cancelGeminiBtn: document.getElementById('cancel-gemini-btn'),
        geminiModalClose: document.getElementById('gemini-modal-close'),
        geminiModalTitle: document.getElementById('gemini-modal-title'),
        addGeminiApiBtn: document.getElementById('add-gemini-api-btn'),
        geminiApisList: document.getElementById('gemini-apis-list'),
        geminiApisCount: document.getElementById('gemini-apis-count'),
        geminiUsageToday: document.getElementById('gemini-usage-today'),
        geminiTotalRequests: document.getElementById('gemini-total-requests'),
        geminiSuccessRate: document.getElementById('gemini-success-rate'),
        usageStats: document.getElementById('usage-stats'),

        // Bulk Gemini API elements
        bulkAddGeminiApiBtn: document.getElementById('bulk-add-gemini-api-btn'),
        bulkGeminiModal: document.getElementById('bulk-gemini-modal'),
        bulkGeminiForm: document.getElementById('bulk-gemini-form'),
        bulkGeminiApiKeys: document.getElementById('bulk-gemini-api-keys'),
        bulkGeminiResults: document.getElementById('bulk-gemini-results'),
        bulkGeminiResultsContent: document.getElementById('bulk-gemini-results-content'),
        saveBulkGeminiBtn: document.getElementById('save-bulk-gemini-btn'),
        cancelBulkGeminiBtn: document.getElementById('cancel-bulk-gemini-btn'),
        bulkGeminiModalClose: document.getElementById('bulk-gemini-modal-close'),

    // Edit Queue Modal
    editQueueModal: document.getElementById('edit-queue-modal'),
    editQueueModalClose: document.getElementById('edit-queue-modal-close'),
    editQueueModalTitle: document.getElementById('edit-queue-modal-title'),
    editQueueForm: document.getElementById('edit-queue-form'),
    editQueueId: document.getElementById('edit-queue-id'),
    editAccountSelect: document.getElementById('edit-account-select'),
    editPageSelect: document.getElementById('edit-page-select'),
    editUploadType: document.querySelectorAll('input[name="edit-upload-type"]'),
    editCaption: document.getElementById('edit-caption'),
    editCaptionLanguage: document.getElementById('edit-caption-language'),
    editGenerateCaptionBtn: document.getElementById('edit-generate-caption-btn'),
    editScheduleTime: document.getElementById('edit-schedule-time'),
    editQueueStatus: document.getElementById('edit-queue-status'),
    editRetryCount: document.getElementById('edit-retry-count'),
    retryCountGroup: document.getElementById('retry-count-group'),
    cancelEditQueueBtn: document.getElementById('cancel-edit-queue-btn'),
    saveEditQueueBtn: document.getElementById('save-edit-queue-btn'),

    // Admin Elements
    adminTab: document.getElementById('admin-tab'),
    addUserBtn: document.getElementById('add-user-btn'),
    userTable: document.getElementById('user-table'),
    userTableBody: document.getElementById('user-table-body'),
    userEmptyState: document.getElementById('user-empty-state'),
    totalUsers: document.getElementById('total-users'),
    activeUsers: document.getElementById('active-users'),
    totalQueues: document.getElementById('total-queues'),
    adminShowBrowser: document.getElementById('admin-show-browser'),
    saveAdminSettingsBtn: document.getElementById('save-admin-settings-btn'),
    refreshAdminDataBtn: document.getElementById('refresh-admin-data-btn'),

    // User Modal Elements
    userModal: document.getElementById('user-modal'),
    userModalClose: document.getElementById('user-modal-close'),
    userModalTitle: document.getElementById('user-modal-title'),
    userForm: document.getElementById('user-form'),
    userId: document.getElementById('user-id'),
    userUsername: document.getElementById('user-username'),
    userDisplayName: document.getElementById('user-display-name'),
    userPassword: document.getElementById('user-password'),
    userConfirmPassword: document.getElementById('user-confirm-password'),
    userRole: document.getElementById('user-role'),
    cancelUserBtn: document.getElementById('cancel-user-btn'),
    saveUserBtn: document.getElementById('save-user-btn')
    };
}

// Setup event listeners
function setupEventListeners() {
    // Navigation tabs
    elements.navTabs.forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Account Management
    elements.addAccountBtn.addEventListener('click', () => openAccountModal());
    elements.saveAccountBtn.addEventListener('click', saveAccount);
    elements.cancelAccountBtn.addEventListener('click', closeAccountModal);
    elements.modalClose.addEventListener('click', closeAccountModal);
    elements.testCookieBtn.addEventListener('click', testCookie);

    // Upload Form - will be modified for web browser file upload
    elements.uploadMode.forEach(radio => radio.addEventListener('change', toggleUploadMode));
    elements.selectFileBtn.addEventListener('click', selectVideoFile);
    elements.selectBulkFilesBtn.addEventListener('click', selectBulkVideoFiles);
    elements.accountSelect.addEventListener('change', () => {
        updatePageSelect();
        updateSendButtonState();
    });
    elements.pageSelect.addEventListener('change', updateSendButtonState);
    elements.videoFile.addEventListener('input', updateSendButtonState);
    elements.bulkFiles.addEventListener('input', updateSendButtonState);
    // Note: bulkInterval and bulkStartTime changes don't affect button state - they're just configuration options

    // Add additional listeners for bulk upload mode changes
    const uploadModeRadios = document.querySelectorAll('input[name="upload-mode"]');
    uploadModeRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            // Small delay to ensure DOM updates are complete
            setTimeout(updateSendButtonState, 50);
        });
    });
    elements.uploadForm.addEventListener('submit', addToQueue);
    elements.addToQueueBtn.addEventListener('click', addToQueue);
    if (elements.bulkGenerateCaptionsBtn) {
        elements.bulkGenerateCaptionsBtn.addEventListener('click', generateBulkCaptions);
    }

    // Queue Management
    elements.refreshQueueBtn.addEventListener('click', refreshQueue);
    if (elements.queueUserSelect) {
        elements.queueUserSelect.addEventListener('change', () => refreshQueue());
    }

    // Settings
    elements.settingsForm.addEventListener('submit', saveSettings);
    elements.resetSettingsBtn.addEventListener('click', resetSettings);

    // Logs
    elements.clearLogsBtn.addEventListener('click', clearLogs);
    elements.exportLogsBtn.addEventListener('click', exportLogs);

        // Gemini AI Caption
        elements.generateCaptionBtn.addEventListener('click', generateCaption);
        elements.addGeminiApiBtn.addEventListener('click', () => openGeminiModal());
        elements.bulkAddGeminiApiBtn.addEventListener('click', () => openBulkGeminiModal());
        elements.saveGeminiBtn.addEventListener('click', saveGeminiApi);
        elements.cancelGeminiBtn.addEventListener('click', closeGeminiModal);
        elements.geminiModalClose.addEventListener('click', closeGeminiModal);
        elements.testGeminiApiBtn.addEventListener('click', testGeminiApi);

        // Bulk Gemini API
        elements.saveBulkGeminiBtn.addEventListener('click', saveBulkGeminiApis);
        elements.cancelBulkGeminiBtn.addEventListener('click', closeBulkGeminiModal);
        elements.bulkGeminiModalClose.addEventListener('click', closeBulkGeminiModal);

        // Edit Queue Modal
        elements.cancelEditQueueBtn.addEventListener('click', closeEditQueueModal);
        elements.editQueueModalClose.addEventListener('click', closeEditQueueModal);
        elements.editQueueForm.addEventListener('submit', saveEditQueueItem);
        elements.editGenerateCaptionBtn.addEventListener('click', generateCaptionForEdit);
        elements.editAccountSelect.addEventListener('change', () => updateEditPageSelect());
        elements.editQueueStatus.addEventListener('change', () => toggleRetryCountGroup());

        // Debug Tab
        if (elements.refreshScreenshotsBtn) {
            elements.refreshScreenshotsBtn.addEventListener('click', refreshScreenshots);
        }
        if (elements.clearTerminalLogsBtn) {
            elements.clearTerminalLogsBtn.addEventListener('click', clearTerminalLogs);
        }
        if (elements.terminalMonitor) {
            setupTerminalTabSwitching();
        }

        // Login/Registration Forms
        if (elements.loginForm) {
            elements.loginForm.addEventListener('submit', handleLoginSubmit);
        }
        if (elements.loginTabBtn) {
            elements.loginTabBtn.addEventListener('click', () => switchLoginTab('login'));
        }
        if (elements.registerTabBtn) {
            elements.registerTabBtn.addEventListener('click', () => switchLoginTab('register'));
        }
        if (elements.registerBtn) {
            elements.registerBtn.addEventListener('click', handleRegister);
        }

        // Logout and User Info
        if (elements.logoutBtn) {
            elements.logoutBtn.addEventListener('click', handleLogout);
        }

        // Change Password Form
    if (elements.changePasswordForm) {
        elements.changePasswordForm.addEventListener('submit', handleChangePassword);
    }

        // Admin Elements Event Listeners
    if (elements.addUserBtn) {
        elements.addUserBtn.addEventListener('click', () => openUserModal());
    }
    if (elements.saveUserBtn) {
        elements.saveUserBtn.addEventListener('click', handleSaveUser);
    }
    if (elements.cancelUserBtn) {
        elements.cancelUserBtn.addEventListener('click', closeUserModal);
    }
    if (elements.userModalClose) {
        elements.userModalClose.addEventListener('click', closeUserModal);
    }
    if (elements.userForm) {
        elements.userForm.addEventListener('submit', handleSaveUser);
    }
    if (elements.saveAdminSettingsBtn) {
        elements.saveAdminSettingsBtn.addEventListener('click', handleSaveAdminSettings);
    }
    if (elements.refreshAdminDataBtn) {
        elements.refreshAdminDataBtn.addEventListener('click', refreshAdminData);
    }
}

// Setup navigation
function setupNavigation() {
    switchTab('accounts'); // Start with accounts tab
}

// Load application data
async function loadAppData() {
    try {
        // Load accounts
        const accountsResponse = await fetch(`${API_BASE}/api/accounts`);
        appState.accounts = await accountsResponse.json();

        // Load queue
        const queueResponse = await fetch(`${API_BASE}/api/queue`);
        appState.uploadQueue = await queueResponse.json();

        // Load settings
        const settingsResponse = await fetch(`${API_BASE}/api/settings`);
        appState.settings = await settingsResponse.json();

        // Update UI
        updateAccountsList();
        updateQueueDisplay();
        updateSettingsDisplay();

        // Load Gemini data in background
        await updateGeminiDisplay();

        // Force button state update after a short delay to ensure all elements are ready
        setTimeout(() => {
            updateSendButtonState();
        }, 100);

        addLog({
            level: 'info',
            message: 'Aplikasi berhasil dimuat',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error loading app data:', error);
        addLog({
            level: 'error',
            message: `Gagal memuat data aplikasi: ${error.message}`,
            timestamp: new Date().toISOString()
        });
    }
}

// Tab switching
function switchTab(tabName) {
    // Update navigation
    elements.navTabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === tabName) {
            tab.classList.add('active');
        }
    });

    // Update content
    elements.tabPanes.forEach(pane => {
        pane.classList.remove('active');
        if (pane.id === tabName) {
            pane.classList.add('active');
        }
    });

    // Show/hide admin-only tabs based on user role
    const isAdmin = appState.user?.role === 'admin' || appState.user?.username === 'admin';

    // Control admin-only tab visibility
    if (elements.adminTab) {
        elements.adminTab.style.display = isAdmin ? 'inline-flex' : 'none';
    }

    // Control analytics tab visibility (admin-only)
    const analyticsTab = Array.from(elements.navTabs).find(tab => tab.dataset?.tab === 'analytics');
    if (analyticsTab) {
        analyticsTab.style.display = isAdmin ? 'inline-flex' : 'none';
    }

    // Control logs tab visibility (admin-only)
    const logsTab = Array.from(elements.navTabs).find(tab => tab.dataset?.tab === 'logs');
    if (logsTab) {
        logsTab.style.display = isAdmin ? 'inline-flex' : 'none';
    }

    // Control debug tab visibility (admin-only)
    const debugTab = Array.from(elements.navTabs).find(tab => tab.dataset?.tab === 'debug');
    if (debugTab) {
        debugTab.style.display = isAdmin ? 'inline-flex' : 'none';
    }

    // Update specific tab content
    updateTabContent(tabName);
}

// Update tab content based on active tab
function updateTabContent(tabName) {
    switch (tabName) {
        case 'accounts':
            updateAccountsList();
            break;
        case 'upload':
            updateSendButtonState(); // Update button state when switching to upload tab
            break;
        case 'queue':
            updateQueueDisplay();
            loadQueueUsers(); // Load users for queue filter
            break;
        case 'analytics':
            loadAnalyticsData();
            loadAnalyticsUsers(); // Load users for analytics filter
            break;
        case 'gemini':
            updateGeminiDisplay();
            break;
        case 'admin':
            loadAdminData();
            break;
        case 'logs':
            updateLogsDisplay();
            break;
        case 'debug':
            loadDebugData();
            break;
    }
}

// Account Management Functions
function openAccountModal(account = null) {
    if (account) {
        elements.accountName.value = account.name;
        elements.accountType.value = 'personal'; // Always personal
        elements.accountCookie.value = ''; // Don't show cookie for security reasons
        elements.accountCookie.placeholder = 'Cookie tersimpan (tidak ditampilkan untuk keamanan)';
        document.getElementById('modal-title').textContent = 'Edit Akun Facebook';
        document.getElementById('save-account-btn').innerHTML = '<i class="fas fa-save"></i> Update & Validasi';
    } else {
        elements.accountName.value = '';
        elements.accountType.value = 'personal'; // Always personal
        elements.accountCookie.value = '';
        elements.accountCookie.placeholder = 'Masukkan cookie Facebook Anda di sini...';
        document.getElementById('modal-title').textContent = 'Tambah Akun Facebook';
        document.getElementById('save-account-btn').innerHTML = '<i class="fas fa-save"></i> Simpan & Validasi';
    }

    elements.accountModal.classList.add('show');
}

function closeAccountModal() {
    elements.accountModal.classList.remove('show');
    elements.accountForm.reset();

    // Reset placeholder text
    elements.accountCookie.placeholder = 'Masukkan cookie Facebook Anda di sini...';
    elements.accountType.value = 'personal'; // Always personal
    document.getElementById('modal-title').textContent = 'Tambah Akun Facebook';
    document.getElementById('save-account-btn').innerHTML = '<i class="fas fa-save"></i> Simpan & Validasi';
}

async function saveAccount(e) {
    e.preventDefault();

    const accountName = elements.accountName.value.trim();
    const accountType = elements.accountType.value;
    const accountCookie = elements.accountCookie.value.trim();

    if (!accountName) {
        showToast('Nama akun harus diisi', 'error');
        return;
    }

    // Check if this is an edit operation (check if account already exists)
    const existingAccount = appState.accounts.find(acc => acc.name === accountName);
    const isEdit = !!existingAccount;

    if (!isEdit && !accountCookie) {
        // For new account, cookie is required
        showToast('Cookie harus diisi untuk akun baru', 'error');
        return;
    }

    // Prepare account data
    const accountData = {
        name: accountName,
        type: accountType,
        cookie: accountCookie
    };

    try {
        elements.saveAccountBtn.disabled = true;
        elements.saveAccountBtn.innerHTML = '<div class="loading"></div> Memvalidasi...';

        let response;
        if (isEdit) {
            // Edit existing account - use PUT endpoint
            response = await fetch(`${API_BASE}/api/accounts/${accountName}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ cookie: accountCookie })
            });
        } else {
            // Create new account - use POST endpoint
            response = await fetch(`${API_BASE}/api/accounts`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(accountData)
            });
        }

        const result = await response.json();

        if (result.success) {
            await loadAppData(); // Reload accounts
            closeAccountModal();

            let message = '';
            if (isEdit) {
                if (result.validation?.fromCache) {
                    message = 'Akun berhasil diupdate (menggunakan validasi sebelumnya)';
                } else {
                    message = 'Akun berhasil diupdate dan divalidasi';
                }
            } else {
                message = 'Akun berhasil disimpan dan divalidasi';
            }

            showToast(message, 'success');

            if (result.pagesCount > 0) {
                showToast(`Ditemukan ${result.pagesCount} halaman Facebook`, 'info');
            }

            if (result.validation?.error) {
                showToast(`Catatan: ${result.validation.error}`, 'warning');
            }
        } else {
            showToast(`Gagal menyimpan akun: ${result.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        elements.saveAccountBtn.disabled = false;
        elements.saveAccountBtn.innerHTML = '<i class="fas fa-save"></i> Simpan & Validasi';
    }
}

async function testCookie() {
    const cookie = elements.accountCookie.value.trim();
    const accountType = elements.accountType.value;

    if (!cookie) {
        showToast('Cookie harus diisi untuk test', 'warning');
        return;
    }

    try {
        elements.testCookieBtn.disabled = true;
        elements.testCookieBtn.innerHTML = '<div class="loading"></div> Testing...';

        const testData = {
            name: elements.accountName.value.trim() || 'Test Account',
            type: accountType,
            cookie: cookie
        };

        const response = await fetch(`${API_BASE}/api/accounts/test`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(testData)
        });
        const result = await response.json();

        if (result.success) {
            const pagesCount = result.pagesCount || result.pages.length;
            showToast(`Test berhasil! Ditemukan ${pagesCount} halaman`, 'success');

            if (result.pages && result.pages.length > 0) {
                console.log('Found pages:', result.pages);
                // Show first few pages in toast
                const pageNames = result.pages.slice(0, 3).map(p => p.name).join(', ');
                const moreText = result.pages.length > 3 ? ` +${result.pages.length - 3} lainnya` : '';
                showToast(`Halaman: ${pageNames}${moreText}`, 'info');
            }
        } else {
            showToast(`Test gagal: ${result.error || result.message}`, 'error');
        }
    } catch (error) {
        showToast(`Test failed: ${error.message}`, 'error');
    } finally {
        elements.testCookieBtn.disabled = false;
        elements.testCookieBtn.innerHTML = '<i class="fas fa-vial"></i> Test Cookie';
    }
}

function updateAccountsList() {
    if (appState.accounts.length === 0) {
        elements.accountsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-users"></i>
                <h3>Belum ada akun</h3>
                <p>Klik tombol "Tambah Akun" untuk menambahkan akun Facebook pertama Anda.</p>
            </div>
        `;
        return;
    }

    elements.accountsList.innerHTML = appState.accounts.map(account => {
        const pagesCount = account.pages ? account.pages.length : 0;
        const pageNames = account.pages ? account.pages.map(page => page.name).slice(0, 3).join(', ') : '';
        const truncatedNames = pagesCount > 3 ? `${pageNames} +${pagesCount - 3} lainnya` : pageNames;

        return `
            <div class="account-card ${account.valid ? 'valid' : 'invalid'}">
                <div class="account-header">
                    <div class="account-name-section">
                        <i class="fas fa-user-circle account-icon"></i>
                        <div class="account-title">
                            <h4>${account.name}</h4>
                            <small class="account-cookie-name">Cookie: ${account.name}</small>
                        </div>
                    </div>
                    <div class="account-status">
                        <span class="status-indicator ${account.valid ? 'status-valid' : 'status-invalid'}">
                            <i class="fas ${account.valid ? 'fa-check-circle' : 'fa-exclamation-triangle'}"></i>
                            ${account.valid ? 'Valid' : 'Tidak Valid'}
                        </span>
                    </div>
                </div>

                <div class="account-details">
                    <div class="account-info-row">
                        <div class="info-item">
                            <i class="fas fa-globe"></i>
                            <span>Tipe: ${account.type === 'personal' ? 'Personal' : 'Page'}</span>
                        </div>
                        <div class="info-item">
                            <i class="fas fa-list"></i>
                            <span>Halaman: ${pagesCount} tersimpan</span>
                        </div>
                    </div>

                    ${pagesCount > 0 ? `
                        <div class="account-pages">
                            <div class="pages-header">
                                <i class="fas fa-flag"></i>
                                <span>List Halaman:</span>
                            </div>
                            <div class="pages-list">
                                ${account.pages.map(page => `
                                    <span class="page-tag" title="${page.name}">
                                        <i class="fab fa-facebook-square"></i>
                                        ${page.name}
                                    </span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>

                <div class="account-actions">
                    <button class="btn-secondary" onclick="editAccount('${account.name}')" title="Edit Akun">
                        <i class="fas fa-edit"></i>
                        Edit
                    </button>
                    <button class="btn-danger" onclick="deleteAccount('${account.name}')" title="Hapus Akun">
                        <i class="fas fa-trash"></i>
                        Hapus
                    </button>
                </div>
            </div>
        `;
    }).join('');

    // Update account select in upload form
    updateAccountSelect();
}

function updateAccountSelect() {
    elements.accountSelect.innerHTML = '<option value="">-- Pilih Akun --</option>' +
        appState.accounts.map(account => `<option value="${account.name}">${account.name}</option>`).join('');

    if (appState.accounts.length > 0) {
        elements.accountSelect.disabled = false;
    } else {
        elements.accountSelect.disabled = true;
    }
}

function updatePageSelect() {
    const selectedAccount = appState.accounts.find(acc => acc.name === elements.accountSelect.value);

    if (selectedAccount && selectedAccount.pages) {
        elements.pageSelect.innerHTML = '<option value="">-- Pilih Halaman --</option>' +
            selectedAccount.pages.map(page => `<option value="${page.id}">${page.name}</option>`).join('');
        elements.pageSelect.disabled = false;
    } else {
        elements.pageSelect.innerHTML = '<option value="">-- Pilih Halaman --</option>';
        elements.pageSelect.disabled = true;
    }
}

// Make functions globally available
window.editAccount = async function(accountName) {
    const account = appState.accounts.find(acc => acc.name === accountName);
    if (account) {
        openAccountModal(account);
    }
};

window.deleteAccount = async function(accountName) {
    if (confirm(`Apakah Anda yakin ingin menghapus akun "${accountName}"?`)) {
        try {
            const response = await fetch(`${API_BASE}/api/accounts/${accountName}`, {
                method: 'DELETE'
            });
            const result = await response.json();

            if (result.success) {
                await loadAppData();
                showToast('Akun berhasil dihapus', 'success');
            } else {
                showToast(`Gagal menghapus akun: ${result.error}`, 'error');
            }
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        }
    }
};

// Upload Functions
async function selectVideoFile() {
    try {
        // Create a hidden file input for web browser file selection
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = 'video/*';
        fileInput.style.display = 'none';

        fileInput.onchange = async (event) => {
            const file = event.target.files[0];
            if (file) {
                // Validate file size before upload (check against server limits)
                const maxFileSize = 500 * 1024 * 1024; // 500MB (server limit)
                if (file.size > maxFileSize) {
                    showToast(`File terlalu besar (${(file.size / (1024 * 1024)).toFixed(1)}MB). Maksimal 500MB.`, 'error');
                    document.body.removeChild(fileInput);
                    return;
                }

                showToast('Mengupload file...', 'info');

                // Upload file to server immediately
                const formData = new FormData();
                formData.append('video', file);

                try {
                    const uploadResponse = await fetch(`${API_BASE}/api/upload`, {
                        method: 'POST',
                        body: formData
                    });

                    // Handle different response types
                    let uploadResult;
                    const contentType = uploadResponse.headers.get('content-type');

                    if (uploadResponse.status === 413) {
                        // Handle 413 Request Entity Too Large
                        showToast('File terlalu besar untuk server. Coba file yang lebih kecil atau hubungi administrator.', 'error');
                        document.body.removeChild(fileInput);
                        return;
                    }

                    if (contentType && contentType.includes('application/json')) {
                        uploadResult = await uploadResponse.json();
                    } else {
                        // Handle HTML error responses (from proxy)
                        const textResponse = await uploadResponse.text();
                        if (uploadResponse.ok) {
                            uploadResult = { success: true, filePath: textResponse };
                        } else {
                            console.error('Server returned HTML error:', textResponse);
                            showToast('Server mengembalikan error yang tidak valid. Coba lagi atau hubungi administrator.', 'error');
                            document.body.removeChild(fileInput);
                            return;
                        }
                    }

                    if (uploadResult.success) {
                        // Keep original filename for AI generation, store uploaded path separately
                        elements.videoFile.value = file.name; // Keep filename for AI
                        elements.videoFile._uploadedFilePath = uploadResult.filePath; // Store actual path for queue
                        elements.videoFile._selectedFile = file;
                        updateSendButtonState();
                        showToast(`File berhasil diupload: ${file.name}`, 'success');
                    } else {
                        showToast(`Upload gagal: ${uploadResult.error}`, 'error');
                    }
                } catch (uploadError) {
                    console.error('Upload error:', uploadError);
                    if (uploadError.name === 'TypeError' && uploadError.message.includes('JSON')) {
                        showToast('Server mengembalikan response yang tidak valid. Kemungkinan file terlalu besar.', 'error');
                    } else {
                        showToast(`Error upload: ${uploadError.message}`, 'error');
                    }
                }
            }
            // Remove the input element
            document.body.removeChild(fileInput);
        };

        // Add to DOM and trigger click
        document.body.appendChild(fileInput);
        fileInput.click();
    } catch (error) {
        showToast(`Error memilih file: ${error.message}`, 'error');
    }
}

// Toggle between single and bulk upload modes
function toggleUploadMode() {
    const isBulkMode = document.querySelector('input[name="upload-mode"]:checked').value === 'bulk';

    if (isBulkMode) {
        document.getElementById('single-upload-interface').style.display = 'none';
        document.getElementById('bulk-upload-interface').style.display = 'block';
        // Clear single upload data
        elements.videoFile.value = '';
        elements.caption.value = '';
        elements.scheduleTime.value = '';
        // Set default start time for bulk uploads
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        elements.bulkStartTime.value = `${year}-${month}-${day}T${hours}:${minutes}`;
    } else {
        document.getElementById('single-upload-interface').style.display = 'block';
        document.getElementById('bulk-upload-interface').style.display = 'none';
        // Clear bulk upload data
        elements.bulkFiles.value = '';
        elements.bulkStartTime.value = '';
        // Reset bulk files list
        const bulkFilesList = elements.bulkFilesList;
        bulkFilesList.innerHTML = '';
        // Clear stored bulk files data
        bulkFilesList._uploadedFiles = [];
        bulkFilesList._selectedFiles = [];
    }

    updateSendButtonState();
}

// Bulk upload progress modal state
let bulkUploadState = {
    isUploading: false,
    totalFiles: 0,
    completedFiles: 0,
    failedFiles: 0,
    currentFile: null,
    startTime: null,
    uploadedFiles: [],
    failedFiles: [],
    timeElapsedInterval: null
};

// Create bulk upload progress modal
function createBulkUploadModal() {
    const modal = document.createElement('div');
    modal.id = 'bulk-upload-modal';
    modal.className = 'modal bulk-upload-modal';
    modal.innerHTML = `
        <div class="modal-content bulk-upload-modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-upload"></i> Upload Bulk Video</h3>
                <button class="modal-close" id="bulk-upload-modal-close">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="bulk-upload-progress">
                <div class="bulk-upload-stats">
                    <div class="stat-item">
                        <span class="stat-label">Total Files:</span>
                        <span class="stat-value" id="bulk-total-files">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Completed:</span>
                        <span class="stat-value" id="bulk-completed-files">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Failed:</span>
                        <span class="stat-value" id="bulk-failed-files">0</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Time Elapsed:</span>
                        <span class="stat-value" id="bulk-time-elapsed">00:00</span>
                    </div>
                </div>
                <div class="bulk-upload-progress-bar">
                    <div class="progress-bar">
                        <div class="progress-fill" id="bulk-progress-fill" style="width: 0%"></div>
                    </div>
                    <div class="progress-text">
                        <span id="bulk-progress-text">0%</span>
                    </div>
                </div>
                <div class="bulk-upload-current">
                    <div class="current-file-info">
                        <i class="fas fa-file-video"></i>
                        <span id="bulk-current-file">Preparing upload...</span>
                    </div>
                    <div class="current-file-status" id="bulk-current-status">
                        <div class="loading-spinner"></div>
                        <span>Initializing...</span>
                    </div>
                </div>
                <div class="bulk-upload-files-list" id="bulk-upload-files-list">
                    <!-- Individual file status will be populated here -->
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" id="bulk-upload-cancel-btn" disabled>
                    <i class="fas fa-times"></i> Cancel Upload
                </button>
                <button class="btn-primary" id="bulk-upload-close-btn" style="display: none;">
                    <i class="fas fa-check"></i> Close
                </button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Add event listeners
    document.getElementById('bulk-upload-modal-close').addEventListener('click', hideBulkUploadModal);
    document.getElementById('bulk-upload-cancel-btn').addEventListener('click', cancelBulkUpload);
    document.getElementById('bulk-upload-close-btn').addEventListener('click', hideBulkUploadModal);

    return modal;
}

// Show bulk upload modal
function showBulkUploadModal() {
    let modal = document.getElementById('bulk-upload-modal');
    if (!modal) {
        modal = createBulkUploadModal();
    }
    modal.classList.add('show');
}

// Hide bulk upload modal
function hideBulkUploadModal() {
    const modal = document.getElementById('bulk-upload-modal');
    if (modal) {
        modal.classList.remove('show');
        // Reset state
        resetBulkUploadState();
    }
}

// Reset bulk upload state
function resetBulkUploadState() {
    bulkUploadState = {
        isUploading: false,
        totalFiles: 0,
        completedFiles: 0,
        failedFiles: 0,
        currentFile: null,
        startTime: null,
        uploadedFiles: [],
        failedFiles: []
    };
}

// Update bulk upload progress
function updateBulkUploadProgress(fileName, status, error = null) {
    const currentFileEl = document.getElementById('bulk-current-file');
    const currentStatusEl = document.getElementById('bulk-current-status');
    const progressFillEl = document.getElementById('bulk-progress-fill');
    const progressTextEl = document.getElementById('bulk-progress-text');
    const completedEl = document.getElementById('bulk-completed-files');
    const failedEl = document.getElementById('bulk-failed-files');
    const timeElapsedEl = document.getElementById('bulk-time-elapsed');

    if (currentFileEl && fileName) {
        currentFileEl.textContent = fileName;
    }

    if (currentStatusEl) {
        let statusHtml = '';
        switch (status) {
            case 'uploading':
                statusHtml = '<div class="loading-spinner"></div><span>Uploading...</span>';
                break;
            case 'success':
                statusHtml = '<i class="fas fa-check-circle text-success"></i><span>Upload successful</span>';
                break;
            case 'error':
                statusHtml = `<i class="fas fa-exclamation-triangle text-error"></i><span>Upload failed${error ? ': ' + error : ''}</span>`;
                break;
            case 'completed':
                statusHtml = '<i class="fas fa-check-circle text-success"></i><span>All uploads completed</span>';
                break;
            default:
                statusHtml = '<div class="loading-spinner"></div><span>Processing...</span>';
        }
        currentStatusEl.innerHTML = statusHtml;
    }

    // Update progress bar
    const progress = bulkUploadState.totalFiles > 0 ?
        ((bulkUploadState.completedFiles + bulkUploadState.failedFiles) / bulkUploadState.totalFiles) * 100 : 0;

    if (progressFillEl) {
        progressFillEl.style.width = `${progress}%`;
    }

    if (progressTextEl) {
        progressTextEl.textContent = `${Math.round(progress)}%`;
    }

    // Update counters
    if (completedEl) {
        completedEl.textContent = bulkUploadState.completedFiles;
    }

    if (failedEl) {
        failedEl.textContent = bulkUploadState.failedFiles;
    }

    // Update time elapsed
    if (timeElapsedEl && bulkUploadState.startTime) {
        const elapsed = Math.floor((Date.now() - bulkUploadState.startTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        timeElapsedEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    // Update file list
    updateBulkUploadFileList();
}

// Update individual file status in the list
function updateBulkUploadFileList() {
    const fileListEl = document.getElementById('bulk-upload-files-list');
    if (!fileListEl) return;

    const allFiles = [...bulkUploadState.uploadedFiles, ...bulkUploadState.failedFiles];
    if (allFiles.length === 0) return;

    fileListEl.innerHTML = allFiles.map((fileData, index) => {
        let statusClass = 'pending';
        let statusIcon = 'fas fa-clock';
        let statusText = 'Pending';

        if (fileData.status === 'success') {
            statusClass = 'success';
            statusIcon = 'fas fa-check-circle';
            statusText = 'Success';
        } else if (fileData.status === 'error') {
            statusClass = 'error';
            statusIcon = 'fas fa-exclamation-triangle';
            statusText = fileData.error || 'Failed';
        }

        return `
            <div class="bulk-upload-file-item ${statusClass}">
                <div class="file-info">
                    <i class="fas fa-file-video"></i>
                    <span class="file-name">${fileData.fileName}</span>
                </div>
                <div class="file-status">
                    <i class="${statusIcon}"></i>
                    <span>${statusText}</span>
                </div>
            </div>
        `;
    }).join('');
}

// Cancel bulk upload
function cancelBulkUpload() {
    if (bulkUploadState.isUploading) {
        bulkUploadState.isUploading = false;

        // Clear the timer
        if (bulkUploadState.timeElapsedInterval) {
            clearInterval(bulkUploadState.timeElapsedInterval);
            bulkUploadState.timeElapsedInterval = null;
        }

        updateBulkUploadProgress(null, 'cancelled');
        showToast('Bulk upload dibatalkan', 'warning');

        // Update modal buttons
        const cancelBtn = document.getElementById('bulk-upload-cancel-btn');
        const closeBtn = document.getElementById('bulk-upload-close-btn');
        if (cancelBtn) cancelBtn.disabled = true;
        if (closeBtn) closeBtn.style.display = 'block';
    }
}

// Bulk file selection with progress tracking
async function selectBulkVideoFiles() {
    try {
        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = 'video/*';
        fileInput.multiple = true;
        fileInput.style.display = 'none';

        fileInput.onchange = async (event) => {
            const files = Array.from(event.target.files);
            if (files.length === 0) {
                document.body.removeChild(fileInput);
                return;
            }

            // Limit to maximum 20 files
            if (files.length > 20) {
                showToast(`Maksimal 20 file video yang dapat dipilih. Anda memilih ${files.length} file.`, 'error');
                document.body.removeChild(fileInput);
                return;
            }

            // Validate file sizes before upload
            const maxFileSize = 500 * 1024 * 1024; // 500MB (server limit)
            const oversizedFiles = files.filter(file => file.size > maxFileSize);

            if (oversizedFiles.length > 0) {
                const oversizedNames = oversizedFiles.map(f => f.name).join(', ');
                showToast(`File terlalu besar: ${oversizedNames}. Maksimal 500MB per file.`, 'error');
                document.body.removeChild(fileInput);
                return;
            }

            // Initialize bulk upload state
            resetBulkUploadState();
            bulkUploadState.totalFiles = files.length;
            bulkUploadState.startTime = Date.now();
            bulkUploadState.isUploading = true;

            // Show progress modal
            showBulkUploadModal();
            updateBulkUploadProgress(null, 'starting');

            // Update modal counters
            document.getElementById('bulk-total-files').textContent = files.length;

            // Start real-time timer for elapsed time
            bulkUploadState.timeElapsedInterval = setInterval(() => {
                if (bulkUploadState.isUploading && bulkUploadState.startTime) {
                    const timeElapsedEl = document.getElementById('bulk-time-elapsed');
                    if (timeElapsedEl) {
                        const elapsed = Math.floor((Date.now() - bulkUploadState.startTime) / 1000);
                        const minutes = Math.floor(elapsed / 60);
                        const seconds = elapsed % 60;
                        timeElapsedEl.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                    }
                }
            }, 1000);

            // Upload all files to server with progress tracking
            const uploadedFiles = [];
            let successCount = 0;
            let errorCount = 0;

            for (let i = 0; i < files.length && bulkUploadState.isUploading; i++) {
                const file = files[i];
                bulkUploadState.currentFile = file.name;

                try {
                    updateBulkUploadProgress(file.name, 'uploading');

                    const formData = new FormData();
                    formData.append('video', file);

                    const uploadResponse = await fetch(`${API_BASE}/api/upload`, {
                        method: 'POST',
                        body: formData
                    });

                    // Handle different response types
                    let uploadResult;
                    const contentType = uploadResponse.headers.get('content-type');

                    if (uploadResponse.status === 413) {
                        // Handle 413 Request Entity Too Large
                        const errorMsg = 'File terlalu besar (413)';
                        console.error(`Upload failed for ${file.name}: ${errorMsg}`);
                        bulkUploadState.failedFiles.push({
                            fileName: file.name,
                            status: 'error',
                            error: errorMsg
                        });
                        errorCount++;
                        bulkUploadState.failedFiles++;
                        continue;
                    }

                    if (contentType && contentType.includes('application/json')) {
                        uploadResult = await uploadResponse.json();
                    } else {
                        // Handle HTML error responses (from proxy)
                        const textResponse = await uploadResponse.text();
                        if (uploadResponse.ok) {
                            uploadResult = { success: true, filePath: textResponse };
                        } else {
                            console.error(`Server returned HTML error for ${file.name}:`, textResponse);
                            const errorMsg = 'Server error';
                            bulkUploadState.failedFiles.push({
                                fileName: file.name,
                                status: 'error',
                                error: errorMsg
                            });
                            errorCount++;
                            bulkUploadState.failedFiles++;
                            continue;
                        }
                    }

                    if (uploadResult.success) {
                        const fileData = {
                            file: uploadResult.filePath,
                            fileName: file.name,
                            selectedFile: file,
                            status: 'success'
                        };
                        uploadedFiles.push(fileData);
                        bulkUploadState.uploadedFiles.push(fileData);
                        successCount++;
                        bulkUploadState.completedFiles++;
                        updateBulkUploadProgress(file.name, 'success');
                    } else {
                        const errorMsg = uploadResult.error || 'Upload failed';
                        console.error(`Upload failed for ${file.name}:`, errorMsg);
                        bulkUploadState.failedFiles.push({
                            fileName: file.name,
                            status: 'error',
                            error: errorMsg
                        });
                        errorCount++;
                        bulkUploadState.failedFiles++;
                        updateBulkUploadProgress(file.name, 'error', errorMsg);
                    }
                } catch (uploadError) {
                    console.error(`Upload error for ${file.name}:`, uploadError);
                    let errorMsg = 'Network error';
                    if (uploadError.name === 'TypeError' && uploadError.message.includes('JSON')) {
                        errorMsg = 'Server response error (file too large?)';
                    }
                    bulkUploadState.failedFiles.push({
                        fileName: file.name,
                        status: 'error',
                        error: errorMsg
                    });
                    errorCount++;
                    bulkUploadState.failedFiles++;
                    updateBulkUploadProgress(file.name, 'error', errorMsg);
                }

                // Small delay between uploads to prevent overwhelming the server
                if (i < files.length - 1 && bulkUploadState.isUploading) {
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
            }

            // Mark upload as completed
            bulkUploadState.isUploading = false;

            // Clear the timer
            if (bulkUploadState.timeElapsedInterval) {
                clearInterval(bulkUploadState.timeElapsedInterval);
                bulkUploadState.timeElapsedInterval = null;
            }

            if (uploadedFiles.length > 0) {
                // Store uploaded files data
                elements.bulkFilesList._uploadedFiles = uploadedFiles;
                elements.bulkFilesList._selectedFiles = uploadedFiles.map(f => f.selectedFile);

                // Update UI
                elements.bulkFiles.value = `${uploadedFiles.length} file dipilih`;
                updateBulkFilesList(uploadedFiles);

                updateBulkUploadProgress(null, 'completed');

                // Show final results
                if (successCount > 0) {
                    showToast(`${successCount} file berhasil diupload`, 'success');
                }
                if (errorCount > 0) {
                    showToast(`${errorCount} file gagal diupload`, 'warning');
                }

                updateSendButtonState();
            } else {
                updateBulkUploadProgress(null, 'completed');
                showToast('Tidak ada file yang berhasil diupload. Pastikan file tidak terlalu besar.', 'error');
                elements.bulkFiles.value = '';
            }

            // Update modal buttons
            const cancelBtn = document.getElementById('bulk-upload-cancel-btn');
            const closeBtn = document.getElementById('bulk-upload-close-btn');
            if (cancelBtn) cancelBtn.disabled = true;
            if (closeBtn) closeBtn.style.display = 'block';

            document.body.removeChild(fileInput);
        };

        document.body.appendChild(fileInput);
        fileInput.click();
    } catch (error) {
        showToast(`Error memilih file: ${error.message}`, 'error');
        hideBulkUploadModal();
    }
}

// Update bulk files list display
function updateBulkFilesList(files) {
    const bulkFilesList = elements.bulkFilesList;
    if (!bulkFilesList) return;

    bulkFilesList.innerHTML = files.map((fileData, index) => `
        <div class="bulk-file-item" data-index="${index}">
            <div class="bulk-file-name">
                <i class="fas fa-file-video"></i>
                ${fileData.fileName}
            </div>
            <button class="bulk-file-remove" onclick="removeBulkFile(${index})">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `).join('');
}

// Remove file from bulk upload
function removeBulkFile(index) {
    const uploadedFiles = elements.bulkFilesList._uploadedFiles || [];
    if (index < 0 || index >= uploadedFiles.length) return;

    uploadedFiles.splice(index, 1);

    if (uploadedFiles.length > 0) {
        elements.bulkFiles.value = `${uploadedFiles.length} file dipilih`;
        updateBulkFilesList(uploadedFiles);
        elements.bulkFilesList._uploadedFiles = uploadedFiles;
        elements.bulkFilesList._selectedFiles = uploadedFiles.map(f => f.selectedFile);
    } else {
        elements.bulkFiles.value = '';
        elements.bulkFilesList.innerHTML = '';
        elements.bulkFilesList._uploadedFiles = [];
        elements.bulkFilesList._selectedFiles = [];
    }

    updateSendButtonState();
}

// Generate captions for bulk upload with round-robin API key assignment
async function generateBulkCaptions() {
    const files = elements.bulkFilesList._uploadedFiles || [];
    const language = elements.bulkCaptionLanguage.value;

    if (files.length === 0) {
        showToast('Tidak ada file untuk generate caption', 'warning');
        return;
    }

    showToast('Generate caption sedang berlangsung...', 'info');

    const generateButton = document.querySelector('.bulk-caption-generation button');
    if (generateButton) {
        generateButton.disabled = true;
        generateButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
    }

    let successCount = 0;
    let errorCount = 0;

    try {
        // Get all available Gemini API keys for round-robin assignment
        const apisResponse = await fetch(`${API_BASE}/api/gemini/apis`);
        const apisResult = await apisResponse.json();

        let availableApis = [];
        if (apisResult && Array.isArray(apisResult)) {
            availableApis = apisResult.filter(api => api.isValid !== false);
        }

        if (availableApis.length === 0) {
            showToast('Tidak ada API key Gemini yang valid tersedia', 'error');
            // Reset button state
            if (generateButton) {
                generateButton.disabled = false;
                generateButton.innerHTML = '<i class="fas fa-magic"></i> Generate Caption';
            }
            return;
        }

        console.log(`🔄 Starting bulk caption generation with ${availableApis.length} API keys for ${files.length} videos`);

        // Process each file with round-robin API key assignment
        for (let i = 0; i < files.length; i++) {
            try {
                const fileData = files[i];
                const fileName = fileData.fileName.split('.').slice(0, -1).join('.'); // Remove extension

                // Round-robin API key assignment: cycle through available APIs
                const apiIndex = i % availableApis.length;
                const assignedApi = availableApis[apiIndex];

                console.log(`🎯 Video ${i + 1}/${files.length} (${fileName}) -> API Key: ${assignedApi.name} (${assignedApi.id})`);

                const result = await fetch(`${API_BASE}/api/gemini/generate-caption`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        fileName,
                        language,
                        apiKeyId: assignedApi.id
                    })
                });
                const response = await result.json();

                if (response.success) {
                    files[i].caption = response.description || '';
                    successCount++;
                    console.log(`✅ Video ${i + 1} caption generated successfully`);
                } else {
                    console.error(`❌ Caption generation failed for ${fileName} (API: ${assignedApi.name}):`, response.error);
                    files[i].caption = `Video ${fileName}`; // Fallback caption
                    errorCount++;
                }
            } catch (error) {
                console.error(`❌ Error generating caption for ${files[i].fileName}:`, error);
                files[i].caption = `Video ${files[i].fileName.split('.').slice(0, -1).join('.')}`; // Fallback
                errorCount++;
            }
        }

        console.log(`📊 Bulk caption generation completed: ${successCount} success, ${errorCount} errors`);

    } catch (apiError) {
        console.error('❌ Error fetching API keys for round-robin assignment:', apiError);
        showToast('Gagal mengambil daftar API key. Menggunakan mode fallback.', 'warning');

        // Fallback: generate without specific API key assignment
        for (let i = 0; i < files.length; i++) {
            try {
                const fileData = files[i];
                const fileName = fileData.fileName.split('.').slice(0, -1).join('.'); // Remove extension

                const result = await fetch(`${API_BASE}/api/gemini/generate-caption`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ fileName, language })
                });
                const response = await result.json();

                if (response.success) {
                    files[i].caption = response.description || '';
                    successCount++;
                } else {
                    console.error(`Caption generation failed for ${fileName}:`, response.error);
                    files[i].caption = `Video ${fileName}`; // Fallback caption
                    errorCount++;
                }
            } catch (error) {
                console.error(`Error generating caption for ${files[i].fileName}:`, error);
                files[i].caption = `Video ${files[i].fileName.split('.').slice(0, -1).join('.')}`; // Fallback
                errorCount++;
            }
        }
    }

    // Update UI with captions
    updateBulkFilesListWithCaptions(files, elements.bulkCaptionLanguage);

    if (generateButton) {
        generateButton.disabled = false;
        generateButton.innerHTML = '<i class="fas fa-magic"></i> Generate Caption';
    }

    if (successCount > 0) {
        showToast(`${successCount} caption berhasil digenerate dengan round-robin API key`, 'success');
    }
    if (errorCount > 0) {
        showToast(`${errorCount} caption menggunakan fallback`, 'warning');
    }
}

// Regenerate caption for a single file in bulk upload with API key rotation
async function regenerateSingleCaption(index) {
    const files = elements.bulkFilesList._uploadedFiles || [];
    if (index < 0 || index >= files.length) {
        showToast('File tidak ditemukan', 'error');
        return;
    }

    const fileData = files[index];
    const fileName = fileData.fileName.split('.').slice(0, -1).join('.'); // Remove extension
    const language = elements.bulkCaptionLanguage.value;

    if (!fileName) {
        showToast('Tidak dapat mengekstrak nama file', 'error');
        return;
    }

    try {
        // Disable the regenerate button temporarily
        const regenerateBtn = document.querySelector(`.bulk-file-item[data-index="${index}"] .bulk-file-regenerate`);
        if (regenerateBtn) {
            regenerateBtn.disabled = true;
            regenerateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        }

        showToast(`Regenerating caption untuk ${fileData.fileName}...`, 'info');

        // Get all available Gemini API keys for rotation
        const apisResponse = await fetch(`${API_BASE}/api/gemini/apis`);
        const apisResult = await apisResponse.json();

        let availableApis = [];
        if (apisResult && Array.isArray(apisResult)) {
            availableApis = apisResult.filter(api => api.isValid !== false);
        }

        if (availableApis.length === 0) {
            throw new Error('Tidak ada API key Gemini yang valid tersedia');
        }

        let success = false;
        let lastError = null;

        // Try each API key until one succeeds
        for (let apiIndex = 0; apiIndex < availableApis.length; apiIndex++) {
            const assignedApi = availableApis[apiIndex];

            try {
                console.log(`🔄 Trying API key: ${assignedApi.name} (${assignedApi.id}) for ${fileData.fileName}`);

                const result = await fetch(`${API_BASE}/api/gemini/generate-caption`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        fileName,
                        language,
                        apiKeyId: assignedApi.id
                    })
                });
                const response = await result.json();

                if (response.success) {
                    // Update the caption in the file data
                    files[index].caption = response.description || '';
                    files[index].captionError = null; // Clear any previous error

                    // Update the UI
                    updateBulkFilesListWithCaptions(files);

                    showToast(`Caption berhasil diregenerate untuk ${fileData.fileName} menggunakan API ${assignedApi.name}!`, 'success');
                    success = true;
                    break; // Exit the loop on success
                } else {
                    lastError = response.error || 'Unknown error';
                    console.warn(`❌ API ${assignedApi.name} failed: ${lastError}`);

                    // Continue to next API if this one failed
                    if (apiIndex < availableApis.length - 1) {
                        console.log(`🔄 Switching to next API key...`);
                        continue;
                    }
                }
            } catch (apiError) {
                lastError = apiError.message || 'API call failed';
                console.warn(`❌ API ${assignedApi.name} error: ${lastError}`);

                // Continue to next API if this one failed
                if (apiIndex < availableApis.length - 1) {
                    console.log(`🔄 Switching to next API key...`);
                    continue;
                }
            }
        }

        // If all APIs failed, show error
        if (!success) {
            files[index].captionError = `All APIs failed. Last error: ${lastError}`;
            files[index].caption = `Video ${fileName}`; // Fallback caption

            // Update the UI to show error state
            updateBulkFilesListWithCaptions(files);

            showToast(`Gagal regenerate caption untuk ${fileData.fileName}: Semua API mencapai limit atau error`, 'error');
        }

    } catch (error) {
        console.error(`Error regenerating caption for ${fileData.fileName}:`, error);

        // Set fallback caption and error
        files[index].caption = `Video ${fileName}`;
        files[index].captionError = error.message || 'Error koneksi';

        // Update the UI
        updateBulkFilesListWithCaptions(files);

        showToast(`Error: ${error.message}`, 'error');
    } finally {
        // Re-enable the regenerate button
        const regenerateBtn = document.querySelector(`.bulk-file-item[data-index="${index}"] .bulk-file-regenerate`);
        if (regenerateBtn) {
            regenerateBtn.disabled = false;
            regenerateBtn.innerHTML = '<i class="fas fa-redo"></i>';
        }
    }
}

// Update bulk files list with captions
function updateBulkFilesListWithCaptions(files) {
    const bulkFilesList = elements.bulkFilesList;
    if (!bulkFilesList) return;

    bulkFilesList.innerHTML = files.map((fileData, index) => `
        <div class="bulk-file-item ${fileData.captionError ? 'caption-error' : ''}" data-index="${index}">
            <div class="bulk-file-name">
                <i class="fas fa-file-video"></i>
                ${fileData.fileName}
                ${fileData.caption ? `<div class="bulk-file-caption">${fileData.caption.substring(0, 100)}${fileData.caption.length > 100 ? '...' : ''}</div>` : ''}
                ${fileData.captionError ? `<div class="bulk-file-error"><i class="fas fa-exclamation-triangle"></i> ${fileData.captionError}</div>` : ''}
            </div>
            <div class="bulk-file-actions">
                <button class="bulk-file-regenerate" onclick="regenerateSingleCaption(${index})" title="Regenerate Caption">
                    <i class="fas fa-redo"></i>
                </button>
                <button class="bulk-file-remove" onclick="removeBulkFile(${index})">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        </div>
    `).join('');
}

async function addToQueue(e) {
    e.preventDefault();

    const isBulkMode = document.querySelector('input[name="upload-mode"]:checked').value === 'bulk';

    if (isBulkMode) {
        // Handle bulk upload
        await handleBulkQueueSubmission();
    } else {
        // Handle single upload
        await handleSingleQueueSubmission();
    }
}

async function handleSingleQueueSubmission() {
    const formData = {
        account: elements.accountSelect.value,
        page: elements.pageSelect.value,
        type: document.querySelector('input[name="upload-type"]:checked').value,
        file: elements.videoFile._uploadedFilePath || elements.videoFile.value, // Use uploaded path for processing
        fileName: elements.videoFile.value, // Keep original filename for AI
        caption: elements.caption.value,
        schedule: elements.scheduleTime.value ? new Date(elements.scheduleTime.value).toISOString() : null
    };

    // No frontend validation - allow submission with any data
    try {
        // Update button state to loading
        updateSendButtonState(true);

        const result = await fetch(`${API_BASE}/api/queue`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        const response = await result.json();

        if (response.success) {
            // Track upload di analytics
            await trackUploadToAnalytics(formData, response.id);

            elements.uploadForm.reset();
            updateSendButtonState(); // Reset button state
            await loadAppData();
            switchTab('queue');
            showToast('Video berhasil ditambahkan ke antrian', 'success');
        } else {
            updateSendButtonState(); // Reset button state
            showToast(`Gagal menambahkan ke antrian: ${response.error}`, 'error');
        }
    } catch (error) {
        updateSendButtonState(); // Reset button state
        showToast(`Error: ${error.message}`, 'error');
    }
}

async function handleBulkQueueSubmission() {
    try {
        const uploadedFiles = elements.bulkFilesList._uploadedFiles || [];
        if (uploadedFiles.length === 0) {
            showToast('Tidak ada file untuk diupload', 'error');
            return;
        }

        // Update button state to loading
        updateSendButtonState(true);

        // Prepare bulk data
        const account = elements.accountSelect.value;
        const page = elements.pageSelect.value;
        const type = document.querySelector('input[name="upload-type"]:checked').value;
        const intervalMinutes = parseInt(elements.bulkInterval.value) || 5;
        const startTimeValue = elements.bulkStartTime.value;

        // Calculate start time - if not specified, use current time for first video
        const startTime = startTimeValue ? new Date(startTimeValue) : new Date();

        // Prepare queue items for bulk upload
        const queueItems = [];
        let uploadedCount = 0;
        let errorCount = 0;

        for (let i = 0; i < uploadedFiles.length; i++) {
            try {
                const fileData = uploadedFiles[i];
                const caption = fileData.caption || `Video ${fileData.fileName.split('.').slice(0, -1).join('.')}`;

                // Calculate schedule time based on interval
                const scheduleTime = new Date(startTime.getTime() + (i * intervalMinutes * 60 * 1000));

                const queueData = {
                    account: account,
                    page: page,
                    type: type,
                    file: fileData.file,
                    fileName: fileData.fileName,
                    caption: caption,
                    schedule: scheduleTime.toISOString(),
                    bulkIndex: i + 1,
                    bulkTotal: uploadedFiles.length
                };

                const result = await fetch(`${API_BASE}/api/queue`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(queueData)
                });
                const response = await result.json();

                if (response.success) {
                    queueItems.push({ ...queueData, id: response.id });
                    // Track upload di analytics
                    await trackUploadToAnalytics(queueData, response.id);
                    uploadedCount++;
                } else {
                    console.error(`Failed to queue item ${i + 1}:`, response.error);
                    errorCount++;
                }
            } catch (itemError) {
                console.error(`Error queuing item ${i + 1}:`, itemError);
                errorCount++;
            }
        }

        if (uploadedCount > 0) {
            // Clear form data
            elements.bulkFiles.value = '';
            if (elements.bulkFilesList) {
                elements.bulkFilesList._uploadedFiles = [];
                elements.bulkFilesList._selectedFiles = [];
                elements.bulkFilesList.innerHTML = '';
            }

            updateSendButtonState(); // Reset button state
            await loadAppData();
            switchTab('queue');

            if (uploadedCount === uploadedFiles.length) {
                showToast(`${uploadedCount} video berhasil ditambahkan ke antrian dengan interval ${intervalMinutes} menit`, 'success');
            } else {
                showToast(`${uploadedCount} video berhasil ditambahkan, ${errorCount} gagal`, 'warning');
            }
        } else {
            updateSendButtonState(); // Reset button state
            showToast('Tidak ada video yang berhasil diantrian', 'error');
        }

    } catch (error) {
        updateSendButtonState(); // Reset button state
        showToast(`Error bulk upload: ${error.message}`, 'error');
        console.error('Bulk upload error:', error);
    }
}

// Update send button state - handles both single and bulk modes
function updateSendButtonState(isLoading = false) {
    const buttonText = elements.addToQueueBtn.querySelector('.btn-text');
    const buttonIcon = elements.addToQueueBtn.querySelector('i');

    if (isLoading) {
        // Loading state - only when actually submitting
        elements.addToQueueBtn.disabled = true;
        buttonText.textContent = 'Mengirim...';
        buttonIcon.className = 'fas fa-paper-plane';
        return;
    }

    const isBulkMode = document.querySelector('input[name="upload-mode"]:checked').value === 'bulk';
    const hasAccount = elements.accountSelect.value;
    const hasPage = elements.pageSelect.value;

    let isValid = false;

    if (isBulkMode) {
        // Bulk mode validation - require account, page, and at least one uploaded file
        const uploadedFiles = elements.bulkFilesList._uploadedFiles || [];
        const hasFiles = uploadedFiles.length > 0;

        // Ensure bulk files list element exists and has the uploaded files data
        const bulkFilesListExists = elements.bulkFilesList && elements.bulkFilesList._uploadedFiles;
        const filesCount = bulkFilesListExists ? elements.bulkFilesList._uploadedFiles.length : 0;

        isValid = hasAccount && hasPage && hasFiles;

        console.log('Bulk Button State Debug:', {
            isBulkMode,
            hasAccount,
            hasPage,
            hasFiles,
            filesCount,
            bulkFilesListExists,
            uploadedFilesLength: uploadedFiles.length,
            isValid
        });
    } else {
        // Single mode validation - require account and page only
        isValid = hasAccount && hasPage;
        console.log('Single Button State Debug:', {
            isBulkMode,
            hasAccount,
            hasPage,
            videoFile: elements.videoFile ? elements.videoFile.value : 'N/A',
            isValid
        });
    }

    elements.addToQueueBtn.disabled = !isValid;
    buttonText.textContent = isBulkMode ? 'Tambahkan ke Antrian Bulk' : 'Kirim ke Facebook';
    buttonIcon.className = 'fas fa-paper-plane';
}

// Queue Management Functions
function updateQueueDisplay() {
    const stats = {
        pending: appState.uploadQueue.filter(item => item.status === 'pending').length,
        processing: appState.uploadQueue.filter(item => item.status === 'processing').length,
        retry: appState.uploadQueue.filter(item => item.status === 'retry').length,
        completed: appState.uploadQueue.filter(item => item.status === 'completed').length,
        failed: appState.uploadQueue.filter(item => item.status === 'failed').length
    };

    elements.pendingCount.textContent = stats.pending;
    elements.processingCount.textContent = stats.processing;
    elements.completedCount.textContent = stats.completed;
    elements.failedCount.textContent = stats.failed;

    // Always show bulk actions, even with empty queue
    const bulkActionsHtml = `
        <div class="queue-bulk-actions">
            <div class="bulk-select-all">
                <label class="checkbox-label">
                    <input type="checkbox" id="select-all-queue" onchange="toggleSelectAll()" ${appState.uploadQueue.length === 0 ? 'disabled' : ''}>
                    <span class="checkmark"></span>
                    Pilih Semua
                </label>
            </div>
            <div class="bulk-action-buttons">
                <button class="btn-warning" id="bulk-retry-btn" onclick="bulkRetrySelected()" disabled>
                    <i class="fas fa-redo"></i> Retry Terpilih
                </button>
                <button class="btn-danger" id="bulk-delete-btn" onclick="bulkDeleteSelected()" disabled>
                    <i class="fas fa-trash"></i> Hapus Terpilih
                </button>
                <button class="btn-danger" id="bulk-delete-all-btn" onclick="bulkDeleteAll()" ${appState.uploadQueue.length === 0 ? 'disabled' : ''}>
                    <i class="fas fa-trash-alt"></i> Hapus Semua
                </button>
            </div>
        </div>
    `;

    if (appState.uploadQueue.length === 0) {
        elements.queueList.innerHTML = bulkActionsHtml + `
            <div class="empty-state">
                <i class="fas fa-list"></i>
                <h3>Antrian kosong</h3>
                <p>Tambahkan video ke antrian untuk mulai upload.</p>
            </div>
        `;
        return;
    }

    elements.queueList.innerHTML = appState.uploadQueue.map(item => {
        // Get account and page information
        const account = appState.accounts.find(acc => acc.name === item.account);
        const page = account?.pages?.find(p => p.id === item.page);
        const accountName = item.account;
        const pageName = page?.name || item.pageName || item.page || 'Unknown';
        const pageId = item.page;

        // Format schedule time if exists
        let scheduleInfo = '';
        if (item.schedule) {
            const scheduleTime = new Date(item.schedule);
            const now = new Date();

            if (scheduleTime > now) {
                // Future schedule - show time remaining
                const timeDiff = scheduleTime - now;
                const hours = Math.floor(timeDiff / (1000 * 60 * 60));
                const minutes = Math.floor((timeDiff % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);

                let timeRemaining = '';
                if (hours > 0) {
                    timeRemaining += `${hours}j `;
                }
                if (minutes > 0 || hours > 0) {
                    timeRemaining += `${minutes}m `;
                }
                timeRemaining += `${seconds}d`;

                scheduleInfo = ` | 🕐 ${scheduleTime.toLocaleString('id-ID')} (dalam ${timeRemaining})`;
            } else {
                // Past schedule - just show date/time
                scheduleInfo = ` | 🕐 ${scheduleTime.toLocaleString('id-ID')}`;
            }
        } else if (item.nextRetry) {
            // Show next retry time for retry status
            const retryTime = new Date(item.nextRetry);
            const now = new Date();
            const timeDiff = retryTime - now;
            const minutes = Math.floor(timeDiff / (1000 * 60));
            const seconds = Math.floor((timeDiff % (1000 * 60)) / 1000);

            if (timeDiff > 0) {
                scheduleInfo = ` | 🔄 Coba lagi dalam ${minutes}m ${seconds}d`;
            } else {
                scheduleInfo = ` | 🔄 Sedang mencoba lagi`;
            }
        }

        // Get cooldown display
        let cooldownHtml = '';
        if (item.cooldownRemaining > 0 && (item.status === 'pending' || item.status === 'scheduled')) {
            const minutes = Math.floor(item.cooldownRemaining / 60);
            const seconds = item.cooldownRemaining % 60;
            cooldownHtml = `<div class="cooldown-info">⏰ Next upload dalam ${minutes}m ${seconds}d</div>`;
        }

        // Get processing logs for processing items
        let processingLogsHtml = '';
        if (item.status === 'processing' && item.processingLogs) {
            const logs = item.processingLogs.split('\n').slice(-8); // Show last 8 logs
            processingLogsHtml = `
                <div class="processing-logs">
                    <h5>Processing Logs:</h5>
                    <div class="logs-content">
                        ${logs.map(log => `<div class="log-line">${log}</div>`).join('')}
                    </div>
                </div>
            `;
        }

        return `
            <div class="queue-item" data-queue-id="${item.id}">
                <div class="queue-item-checkbox">
                    <label class="checkbox-label">
                        <input type="checkbox" class="queue-item-checkbox-input" value="${item.id}" onchange="updateBulkActionButtons()">
                        <span class="checkmark"></span>
                    </label>
                </div>
                <div class="queue-item-info">
                    <div class="queue-item-meta">Akun: ${accountName} | Halaman: ${pageName}-${pageId} | ${item.type === 'reel' ? 'Reels' : 'Video Post'}${scheduleInfo}</div>
                    <div class="queue-item-title">${item.caption || 'Tanpa caption'}</div>
                    ${cooldownHtml}
                    ${processingLogsHtml}
                </div>
                <div class="queue-item-status ${item.status}">
                    ${item.status}
                </div>
                <div class="queue-item-actions">
                    ${item.status === 'retry' || item.status === 'failed' ? `
                        <button class="btn-warning" onclick="retryQueueItem('${item.id}')" title="Retry Upload">
                            <i class="fas fa-redo"></i>
                        </button>
                    ` : ''}
                    ${item.status === 'retry' ? `
                        <div class="queue-item-info-retry">
                            <small>${item.retryCount || 0}/${appState.settings.maxRetries || 3} percobaan</small>
                            ${item.nextRetry ? `<small>Next: ${new Date(item.nextRetry).toLocaleString()}</small>` : ''}
                            ${item.errorMessage ? `<small class="error-msg">${item.errorMessage}</small>` : ''}
                        </div>
                    ` : ''}
                    ${item.status === 'failed' ? `
                        <div class="queue-item-info-failed">
                            <small class="error-msg">${item.errorMessage || 'Upload gagal'}</small>
                            <small>${item.retryCount || 0} percobaan gagal</small>
                        </div>
                    ` : ''}
                    ${item.status === 'pending' || item.status === 'scheduled' ? `
                        <button class="btn-secondary" onclick="editQueueItem('${item.id}')" title="Edit Item">
                            <i class="fas fa-edit"></i>
                        </button>
                    ` : ''}
                    <button class="btn-danger" onclick="removeFromQueue('${item.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `;
    }).join('');

    updateStatusBar();
}

window.retryQueueItem = async function(itemId) {
    if (confirm('Apakah Anda yakin ingin mencoba upload ulang item ini?')) {
        try {
            // Reset the item status to pending and reset retry count
            const response = await fetch(`${API_BASE}/api/queue/${itemId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    status: 'pending',
                    retryCount: 0, // Reset retry count for manual retry
                    errorMessage: null // Clear error message
                })
            });
            const result = await response.json();

            if (result.success) {
                await loadAppData();
                showToast('Item berhasil diatur untuk retry', 'success');
            } else {
                // Handle different error types
                if (response.status === 409) {
                    showToast('Item sedang diproses. Tunggu hingga proses selesai sebelum mencoba lagi.', 'warning');
                } else if (response.status === 403) {
                    showToast('Akses ditolak: Item milik user lain', 'error');
                } else if (response.status === 404) {
                    showToast('Item tidak ditemukan. Mungkin sudah dihapus.', 'error');
                } else {
                    showToast(`Gagal mengatur retry: ${result.error}`, 'error');
                }
            }
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        }
    }
};

window.editQueueItem = async function(itemId) {
    const item = appState.uploadQueue.find(q => q.id === itemId);
    if (!item) {
        showToast('Item tidak ditemukan', 'error');
        return;
    }

    // Populate edit modal with current data
    openEditQueueModal(item);
};

// Make function globally available
window.removeFromQueue = async function(itemId) {
    if (confirm('Apakah Anda yakin ingin menghapus item ini dari antrian?')) {
        try {
            const response = await fetch(`${API_BASE}/api/queue/${itemId}`, {
                method: 'DELETE'
            });
            const result = await response.json();

            if (result.success) {
                await loadAppData();
                showToast('Item berhasil dihapus dari antrian', 'success');
            } else {
                showToast(`Gagal menghapus item: ${result.error}`, 'error');
            }
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        }
    }
};

async function startQueue() {
    try {
        elements.startQueueBtn.disabled = true;
        elements.startQueueBtn.innerHTML = '<div class="loading"></div> Memulai...';

        // Start queue processing using API
        const result = await fetch(`${API_BASE}/api/queue/start`, {
            method: 'POST'
        });
        const response = await result.json();

        if (response.success) {
            showToast('Antrian dimulai', 'success');
            await loadAppData(); // Reload queue data
        } else {
            showToast(`Gagal memulai antrian: ${response.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        elements.startQueueBtn.disabled = false;
        elements.startQueueBtn.innerHTML = '<i class="fas fa-play"></i> Mulai Proses';
    }
}

async function pauseQueue() {
    showToast('Fitur pause akan diimplementasikan', 'info');
}

async function clearQueue() {
    if (confirm('Apakah Anda yakin ingin membersihkan seluruh antrian?')) {
        try {
            // Remove all items from queue
            for (const item of appState.uploadQueue) {
                await fetch(`${API_BASE}/api/queue/${item.id}`, {
                    method: 'DELETE'
                });
            }
            await loadAppData();
            showToast('Antrian berhasil dibersihkan', 'success');
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        }
    }
}

async function refreshQueue() {
    try {
        // Get selected user filter
        const selectedUserId = elements.queueUserSelect ? elements.queueUserSelect.value : '';

        // Build URL with user filter if admin and user selected
        let url = `${API_BASE}/api/queue`;
        if (selectedUserId && (appState.user?.role === 'admin' || appState.user?.username === 'admin')) {
            url += `?userId=${selectedUserId}`;
        }

        // Refresh queue data
        const queueResponse = await fetch(url);
        const newQueue = await queueResponse.json();
        appState.uploadQueue = newQueue;
        updateQueueDisplay();
        showToast('Status antrian diperbaharui', 'success');
    } catch (error) {
        showToast(`Gagal memperbaharui status antrian: ${error.message}`, 'error');
    }
}

// Load users for filter dropdown (admin only)
async function loadQueueUsers() {
    const isAdmin = appState.user?.role === 'admin' || appState.user?.username === 'admin';

    if (!isAdmin) {
        // Hide user filter for non-admin users
        if (elements.queueFilter) {
            elements.queueFilter.style.display = 'none';
        }
        return;
    }

    // Show user filter for admin users
    if (elements.queueFilter) {
        elements.queueFilter.style.display = 'block';
    }

    try {
        const usersResponse = await fetch(`${API_BASE}/api/admin/users`);
        const usersResult = await usersResponse.json();

        if (usersResult.success && usersResult.users) {
            // Populate user dropdown
            const userSelect = elements.queueUserSelect;
            if (userSelect) {
                userSelect.innerHTML = '<option value="">-- Semua User --</option>' +
                    usersResult.users.map(user => `<option value="${user.id}">${user.displayName} (${user.username})</option>`).join('');
            }
        }
    } catch (error) {
        console.error('Error loading users for queue filter:', error);
        if (elements.queueFilter) {
            elements.queueFilter.style.display = 'none';
        }
    }
}

async function processQueue() {
    // This would be implemented with the actual queue processing logic
    addLog({
        level: 'info',
        message: 'Memproses antrian upload...',
        timestamp: new Date().toISOString()
    });
}

// Settings Functions
function updateSettingsDisplay() {
    if (elements.uploadDelay) {
        elements.uploadDelay.value = appState.settings.uploadDelay / 1000; // Convert to seconds
    }
    if (elements.maxRetries) {
        elements.maxRetries.value = appState.settings.maxRetries;
    }
    if (elements.autoStartQueue) {
        elements.autoStartQueue.checked = appState.settings.autoStartQueue;
    }
    if (elements.showNotifications) {
        elements.showNotifications.checked = appState.settings.showNotifications;
    }
    // showBrowser is only available in admin panel, not in regular user settings
    // if (elements.showBrowser) {
    //     elements.showBrowser.checked = appState.settings.showBrowser;
    // }
}

async function saveSettings(e) {
    e.preventDefault();

    // Check if required elements exist
    if (!elements.uploadDelay || !elements.maxRetries || !elements.autoStartQueue || !elements.showNotifications) {
        console.error('Settings form elements not found');
        showToast('Error: Form elements not loaded properly', 'error');
        return;
    }

    // Get values with fallbacks to prevent undefined errors
    const uploadDelayValue = elements.uploadDelay.value || '30';
    const maxRetriesValue = elements.maxRetries.value || '3';

    const newSettings = {
        uploadDelay: parseInt(uploadDelayValue) * 1000, // Convert to milliseconds
        maxRetries: parseInt(maxRetriesValue),
        autoStartQueue: elements.autoStartQueue.checked || false,
        showNotifications: elements.showNotifications.checked || false
    };

    try {
        const result = await fetch(`${API_BASE}/api/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newSettings)
        });
        const response = await result.json();

        if (response.success) {
            appState.settings = newSettings;
            showToast('Pengaturan berhasil disimpan', 'success');
        } else {
            showToast(`Gagal menyimpan pengaturan: ${response.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    }
}

function resetSettings() {
    if (confirm('Apakah Anda yakin ingin mengembalikan pengaturan ke default?')) {
        appState.settings = {
            uploadDelay: 30000,
            maxRetries: 3,
            autoStartQueue: false,
            showNotifications: true,
            showBrowser: false
        };
        updateSettingsDisplay();
        saveSettings(new Event('submit'));
    }
}

// Logs Functions
function addLog(logEntry) {
    appState.logs.unshift(logEntry);
    // Keep only last 1000 logs
    if (appState.logs.length > 1000) {
        appState.logs = appState.logs.slice(0, 1000);
    }
    updateLogsDisplay();
}

function updateLogsDisplay() {
    if (appState.logs.length === 0) {
        elements.logsContainer.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-terminal"></i>
                <h3>Belum ada aktivitas</h3>
                <p>Log aktivitas akan muncul di sini saat aplikasi berjalan.</p>
            </div>
        `;
        return;
    }

    elements.logsContainer.innerHTML = appState.logs.map(log => `
        <div class="log-entry">
            <span class="log-timestamp">${new Date(log.timestamp).toLocaleTimeString()}</span>
            <span class="log-level ${log.level}">${log.level.toUpperCase()}</span>
            <span class="log-message">${log.message}</span>
        </div>
    `).join('');

    // Scroll to top
    elements.logsContainer.scrollTop = 0;
}

function clearLogs() {
    if (confirm('Apakah Anda yakin ingin menghapus semua log?')) {
        appState.logs = [];
        updateLogsDisplay();
        showToast('Log berhasil dibersihkan', 'success');
    }
}

function exportLogs() {
    if (appState.logs.length === 0) {
        showToast('Tidak ada log untuk diekspor', 'warning');
        return;
    }

    const logContent = appState.logs.map(log =>
        `[${new Date(log.timestamp).toLocaleString()}] ${log.level.toUpperCase()}: ${log.message}`
    ).join('\n');

    const blob = new Blob([logContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `reelsync-logs-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('Log berhasil diekspor', 'success');
}

// Utility Functions
function updateStatusBar() {
    const pendingCount = appState.uploadQueue.filter(item => item.status === 'pending').length;
    elements.queueStatus.textContent = `Antrian: ${pendingCount} item`;

    if (pendingCount > 0) {
        elements.statusText.textContent = 'Antrian siap diproses';
    } else {
        elements.statusText.textContent = 'Siap digunakan';
    }
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);

    // Also log the message
    addLog({
        level: type,
        message: message,
        timestamp: new Date().toISOString()
    });
}

function handleAccountValidation(result) {
    if (result.success) {
        showToast('Akun berhasil divalidasi', 'success');
    } else {
        showToast(`Validasi akun gagal: ${result.error}`, 'error');
    }
}

// Handle modal click outside
elements.accountModal?.addEventListener('click', (e) => {
    if (e.target === elements.accountModal) {
        closeAccountModal();
    }
});

// Gemini AI Caption Functions
async function generateCaption() {
    const filePath = elements.videoFile.value;
    const language = elements.captionLanguage.value;

    if (!filePath) {
        showToast('Pilih file video terlebih dahulu', 'warning');
        return;
    }

    // Extract filename from path
    const fileName = filePath.split(/[/\\]/).pop();

    if (!fileName) {
        showToast('Tidak dapat mengekstrak nama file', 'error');
        return;
    }

    try {
        elements.generateCaptionBtn.disabled = true;
        elements.generateCaptionBtn.innerHTML = '<div class="loading"></div> Generating...';

        // Call Gemini service through API
        const result = await fetch(`${API_BASE}/api/gemini/generate-caption`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ fileName, language })
        });
        const response = await result.json();

        if (response.success) {
            elements.caption.value = response.description || '';
            showToast('Caption berhasil digenerate!', 'success');
        } else {
            showToast(`Gagal generate caption: ${response.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        elements.generateCaptionBtn.disabled = false;
        elements.generateCaptionBtn.innerHTML = '<i class="fas fa-magic"></i> Generate Caption';
    }
}

function openGeminiModal(api = null) {
    if (api) {
        elements.geminiApiName.value = api.name;
        elements.geminiApiKey.value = ''; // Don't show key for security
        elements.geminiApiKey.placeholder = 'API key tersimpan (tidak ditampilkan)';
        elements.geminiModalTitle.textContent = 'Edit API Key Gemini';
        elements.saveGeminiBtn.innerHTML = '<i class="fas fa-save"></i> Update API Key';
    } else {
        elements.geminiForm.reset();
        elements.geminiApiKey.placeholder = 'Masukkan API key Gemini Anda...';
        elements.geminiModalTitle.textContent = 'Tambah API Key Gemini';
        elements.saveGeminiBtn.innerHTML = '<i class="fas fa-save"></i> Simpan API Key';
    }

    elements.geminiModal.classList.add('show');
}

function closeGeminiModal() {
    elements.geminiModal.classList.remove('show');
    elements.geminiForm.reset();
    elements.geminiApiKey.placeholder = 'Masukkan API key Gemini Anda...';
    elements.geminiModalTitle.textContent = 'Tambah API Key Gemini';
    elements.saveGeminiBtn.innerHTML = '<i class="fas fa-save"></i> Simpan API Key';
}

async function saveGeminiApi(e) {
    e.preventDefault();

    const apiName = elements.geminiApiName.value.trim();
    const apiKey = elements.geminiApiKey.value.trim();

    if (!apiName) {
        showToast('Nama API key harus diisi', 'error');
        return;
    }

    // Check if editing (no new key provided)
    const existingApi = appState.geminiApis?.find(api => api.name === apiName);
    const isEdit = !!existingApi;

    if (isEdit && !apiKey) {
        // For edit, if no new key, just update name (this case may not happen in web app)
        showToast('Tidak dapat edit API tanpa key baru pada web app', 'warning');
        return;
    } else if (!isEdit && !apiKey) {
        showToast('API key harus diisi untuk yang baru', 'error');
        return;
    } else {
        // New API
        const apiData = {
            name: apiName,
            apiKey: apiKey
        };

        try {
            elements.saveGeminiBtn.disabled = true;
            elements.saveGeminiBtn.innerHTML = '<div class="loading"></div> Saving...';

            const result = await fetch(`${API_BASE}/api/gemini/apis`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(apiData)
            });
            const response = await result.json();

            if (response.success) {
                await updateGeminiDisplay();
                closeGeminiModal();
                showToast('API key berhasil disimpan', 'success');
            } else {
                showToast(`Gagal menyimpan API key: ${response.error}`, 'error');
            }
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        } finally {
            elements.saveGeminiBtn.disabled = false;
            elements.saveGeminiBtn.innerHTML = '<i class="fas fa-save"></i> Simpan API Key';
        }
    }
}

async function testGeminiApi() {
    const apiKey = elements.geminiApiKey.value.trim();

    if (!apiKey) {
        showToast('API key harus diisi untuk test', 'warning');
        return;
    }

    try {
        elements.testGeminiApiBtn.disabled = true;
        elements.testGeminiApiBtn.innerHTML = '<div class="loading"></div> Testing...';

        const result = await fetch(`${API_BASE}/api/gemini/test-key`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ apiKey })
        });
        const response = await result.json();

        if (response.success) {
            showToast('API key valid! Gemini siap digunakan', 'success');
        } else {
            showToast(`Test gagal: ${response.error || 'API key tidak valid'}`, 'error');
        }
    } catch (error) {
        showToast(`Test failed: ${error.message}`, 'error');
    } finally {
        elements.testGeminiApiBtn.disabled = false;
        elements.testGeminiApiBtn.innerHTML = '<i class="fas fa-vial"></i> Test API Key';
    }
}

async function updateGeminiDisplay() {
    try {
        // Load Gemini APIs
        const apisResponse = await fetch(`${API_BASE}/api/gemini/apis`);
        const apis = await apisResponse.json();
        appState.geminiApis = apis;

        // Update stats
        elements.geminiApisCount.textContent = apis.length;

        if (apis.length === 0) {
            elements.geminiApisList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-key"></i>
                    <h3>Belum ada API Key</h3>
                    <p>Tambahkan API key Gemini untuk mulai generate caption otomatis.</p>
                </div>
            `;
        } else {
            elements.geminiApisList.innerHTML = apis.map(api => `
                <div class="gemini-api-card">
                    <div class="api-info">
                        <h4>${api.name}</h4>
                        <p>Status: ${api.isValid ? 'Valid' : 'Tidak Valid'}</p>
                        <small>Created: ${new Date(api.createdAt).toLocaleDateString()}</small>
                    </div>
                    <div class="api-actions">
                        <button class="btn-secondary" onclick="editGeminiApi('${api.id}')">
                            <i class="fas fa-edit"></i>
                        </button>
                        <button class="btn-danger" onclick="deleteGeminiApi('${api.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </div>
            `).join('');
        }

        // Load usage stats
        const statsResponse = await fetch(`${API_BASE}/api/gemini/stats`);
        const stats = await statsResponse.json();
        if (stats) {
            elements.geminiUsageToday.textContent = stats.recentRequests || 0;
            elements.geminiSuccessRate.textContent = stats.recentSuccessRate || '0%';
            elements.geminiTotalRequests.textContent = stats.totalRequests || 0;
        }

    } catch (error) {
        console.error('Error updating Gemini display:', error);
        showToast(`Error loading Gemini data: ${error.message}`, 'error');
    }
}

// Make functions globally available
window.editGeminiApi = async function(apiId) {
    const api = appState.geminiApis.find(a => a.id === parseInt(apiId));
    if (api) {
        openGeminiModal(api);
    }
};

window.deleteGeminiApi = async function(apiId) {
    if (confirm('Apakah Anda yakin ingin menghapus API key ini?')) {
        try {
            const response = await fetch(`${API_BASE}/api/gemini/apis/${apiId}`, {
                method: 'DELETE'
            });
            const result = await response.json();

            if (result.success) {
                await updateGeminiDisplay();
                showToast('API key berhasil dihapus', 'success');
            } else {
                showToast(`Gagal menghapus API key: ${result.error || 'API key tidak ditemukan'}`, 'error');
            }
        } catch (error) {
            showToast(`Error: ${error.message}`, 'error');
        }
    }
};

// Handle modal click outside
elements.geminiModal?.addEventListener('click', (e) => {
    if (e.target === elements.geminiModal) {
        closeGeminiModal();
    }
});

// Bulk Gemini API Functions
function openBulkGeminiModal() {
    elements.bulkGeminiForm.reset();
    elements.bulkGeminiResults.style.display = 'none';
    elements.bulkGeminiResultsContent.innerHTML = '';
    elements.bulkGeminiModal.classList.add('show');
}

function closeBulkGeminiModal() {
    elements.bulkGeminiModal.classList.remove('show');
    elements.bulkGeminiForm.reset();
    elements.bulkGeminiResults.style.display = 'none';
    elements.bulkGeminiResultsContent.innerHTML = '';
}

async function saveBulkGeminiApis(e) {
    e.preventDefault();

    const apiKeysText = elements.bulkGeminiApiKeys.value.trim();

    if (!apiKeysText) {
        showToast('API keys harus diisi', 'error');
        return;
    }

    // Split by lines and filter out empty lines
    const apiKeys = apiKeysText.split('\n')
        .map(key => key.trim())
        .filter(key => key.length > 0);

    if (apiKeys.length === 0) {
        showToast('Tidak ada API key yang valid', 'error');
        return;
    }

    if (apiKeys.length > 50) {
        showToast('Maksimal 50 API keys sekaligus', 'error');
        return;
    }

    try {
        elements.saveBulkGeminiBtn.disabled = true;
        elements.saveBulkGeminiBtn.innerHTML = '<div class="loading"></div> Menyimpan...';

        // Show results section
        elements.bulkGeminiResults.style.display = 'block';
        elements.bulkGeminiResultsContent.innerHTML = '<div class="bulk-result-item"><div class="loading"></div> Memproses API keys...</div>';

        const results = [];
        let successCount = 0;
        let errorCount = 0;

        // Process each API key
        for (let i = 0; i < apiKeys.length; i++) {
            const apiKey = apiKeys[i];
            const apiName = `API Key ${i + 1}`;

            try {
                const result = await fetch(`${API_BASE}/api/gemini/apis`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: apiName,
                        apiKey: apiKey
                    })
                });
                const response = await result.json();

                if (response.success) {
                    results.push({
                        index: i + 1,
                        name: apiName,
                        status: 'success',
                        message: 'Berhasil disimpan'
                    });
                    successCount++;
                } else {
                    results.push({
                        index: i + 1,
                        name: apiName,
                        status: 'error',
                        message: response.error || 'Gagal menyimpan'
                    });
                    errorCount++;
                }
            } catch (error) {
                results.push({
                    index: i + 1,
                    name: apiName,
                    status: 'error',
                    message: error.message || 'Error koneksi'
                });
                errorCount++;
            }

            // Update progress display
            updateBulkResultsDisplay(results);
        }

        // Final update
        updateBulkResultsDisplay(results);

        if (successCount > 0) {
            await updateGeminiDisplay(); // Refresh the main display
            showToast(`${successCount} API keys berhasil disimpan`, 'success');
        }

        if (errorCount > 0) {
            showToast(`${errorCount} API keys gagal disimpan`, 'warning');
        }

    } catch (error) {
        showToast(`Error bulk save: ${error.message}`, 'error');
    } finally {
        elements.saveBulkGeminiBtn.disabled = false;
        elements.saveBulkGeminiBtn.innerHTML = '<i class="fas fa-save"></i> Simpan API Keys';
    }
}

function updateBulkResultsDisplay(results) {
    elements.bulkGeminiResultsContent.innerHTML = results.map(result => `
        <div class="bulk-result-item ${result.status}">
            <div class="result-info">
                <span class="result-index">#${result.index}</span>
                <span class="result-name">${result.name}</span>
            </div>
            <div class="result-status">
                <i class="fas ${result.status === 'success' ? 'fa-check-circle' : 'fa-exclamation-triangle'}"></i>
                <span>${result.message}</span>
            </div>
        </div>
    `).join('');
}

// Handle modal click outside for bulk gemini modal
elements.bulkGeminiModal?.addEventListener('click', (e) => {
    if (e.target === elements.bulkGeminiModal) {
        closeBulkGeminiModal();
    }
});

// Handle escape key for modals
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && elements.accountModal.classList.contains('show')) {
        closeAccountModal();
    }
    if (e.key === 'Escape' && elements.geminiModal.classList.contains('show')) {
        closeGeminiModal();
    }
    if (e.key === 'Escape' && elements.editQueueModal.classList.contains('show')) {
        closeEditQueueModal();
    }
});

// Load users for analytics filter dropdown (admin only)
async function loadAnalyticsUsers() {
    const isAdmin = appState.user?.role === 'admin' || appState.user?.username === 'admin';

    if (!isAdmin) {
        // Hide user filter for non-admin users
        const userFilterSelect = document.getElementById('user-filter-select');
        if (userFilterSelect) {
            userFilterSelect.style.display = 'none';
        }
        return;
    }

    // Show user filter for admin users
    const userFilterSelect = document.getElementById('user-filter-select');
    if (userFilterSelect) {
        userFilterSelect.style.display = 'inline-block';
    }

    try {
        const usersResponse = await fetch(`${API_BASE}/api/admin/users`);
        const usersResult = await usersResponse.json();

        if (usersResult.success && usersResult.users) {
            // Populate user dropdown
            const userSelect = document.getElementById('user-filter-select');
            if (userSelect) {
                userSelect.innerHTML = '<option value="">-- Semua User --</option>' +
                    usersResult.users.map(user => `<option value="${user.id}">${user.displayName} (${user.username})</option>`).join('');
            }
        }
    } catch (error) {
        console.error('Error loading users for analytics filter:', error);
        const userFilterSelect = document.getElementById('user-filter-select');
        if (userFilterSelect) {
            userFilterSelect.style.display = 'none';
        }
    }
}

// Analytics Functions
async function loadAnalyticsData() {
    if (analyticsState.isLoading) {
        console.log('Analytics already loading, skipping...');
        return;
    }

    try {
        analyticsState.isLoading = true;
        console.log(`📊 Loading analytics data for ${analyticsState.currentTimeRange}, user filter: ${analyticsState.currentUserFilter}`);

        // Show loading state
        showAnalyticsLoading();

        // Build query parameters
        const params = new URLSearchParams({
            timeRange: analyticsState.currentTimeRange
        });

        if (analyticsState.currentUserFilter) {
            params.append('userId', analyticsState.currentUserFilter);
        }

        const result = await fetch(`${API_BASE}/api/analytics?${params}`);
        const response = await result.json();

        if (response.success) {
            analyticsState.dashboardData = response.data;
            updateAnalyticsDisplay();
            console.log('✅ Analytics display updated');
        } else {
            console.error('❌ Failed to load analytics:', response.error);
            showAnalyticsEmpty();
        }
    } catch (error) {
        console.error('❌ Error loading analytics data:', error);
        showAnalyticsEmpty();
    } finally {
        analyticsState.isLoading = false;
        console.log('📊 Analytics loading completed');
    }
}

function showAnalyticsLoading() {
    const sections = [
        'overview-stats',
        'performance-by-type',
        'account-comparison',
        'category-performance',
        'trends-chart'
    ];

    sections.forEach(sectionId => {
        const element = document.getElementById(sectionId);
        if (element) {
            element.innerHTML = `
                <div class="analytics-loading">
                    <div class="loading"></div>
                    <span>Memuat data...</span>
                </div>
            `;
        }
    });
}

function showAnalyticsEmpty() {
    const sections = [
        'overview-stats',
        'performance-by-type',
        'account-comparison',
        'category-performance',
        'trends-chart'
    ];

    sections.forEach(sectionId => {
        const element = document.getElementById(sectionId);
        if (element) {
            element.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-chart-bar"></i>
                    <h3>Belum ada data</h3>
                    <p>Data analytics akan muncul setelah upload pertama.</p>
                </div>
            `;
        }
    });
}

function updateAnalyticsDisplay() {
    const data = analyticsState.dashboardData || {};

    // Update overview stats
    updateOverviewStats(data.overview);

    // Update performance by type
    updatePerformanceByType(data.performance);

    // Update account comparison
    updateAccountComparison(data.accounts);



    // Update category performance
    updateCategoryPerformance(data.categories);

    // Update trends chart
    updateTrendsChart(data.trends);

    console.log('✅ Analytics display fully updated');
}

function updateOverviewStats(overview) {
    const statsMap = {
        'total-uploads': overview?.totalUploads || 0,
        'success-rate': overview?.successRate ? `${overview.successRate.toFixed(1)}%` : '0%',
        'total-views': overview?.totalViews || 0,
        'avg-engagement': overview?.averageEngagementRate ? `${overview.averageEngagementRate.toFixed(1)}%` : '0%'
    };

    Object.entries(statsMap).forEach(([elementId, value]) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = value;
            // Also remove loading state if present
            const loadingParent = element.closest('.analytics-loading');
            if (loadingParent) {
                loadingParent.remove();
            }
        }
    });

    // If we have overview data but it's all zeros, this might still be empty state
    const hasData = overview && (overview.totalUploads > 0 || overview.totalViews > 0);
    if (!hasData) {
        const container = document.getElementById('overview-stats');
        if (container) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-chart-line"></i>
                    <h3>Belum ada overview</h3>
                    <p>Stats overview akan muncul setelah upload pertama.</p>
                </div>
            `;
        }
    }
}

function updatePerformanceByType(performance) {
    if (!performance) return;

    const container = document.getElementById('performance-by-type');
    if (!container) return;

    const reels = performance.byType?.reels || {};
    const posts = performance.byType?.posts || {};

    container.innerHTML = `
        <div class="performance-comparison">
            <div class="performance-card">
                <h4><i class="fas fa-video"></i> Facebook Reels</h4>
                <div class="stat-number">${reels.uploads || 0}</div>
                <div class="stat-label">Total All User Uploads</div>
                <div class="performance-details">
                    <div class="performance-detail">
                        <span class="detail-label">Views:</span>
                        <span class="detail-value">${reels.views || 0}</span>
                    </div>
                    <div class="performance-detail">
                        <span class="detail-label">Avg Engagement:</span>
                        <span class="detail-value">${reels.engagementRate?.toFixed(1) || 0}%</span>
                    </div>
                </div>
            </div>
            <div class="performance-card">
                <h4><i class="fas fa-film"></i> Video Posts</h4>
                <div class="stat-number">${posts.uploads || 0}</div>
                <div class="stat-label">Total All User Uploads</div>
                <div class="performance-details">
                    <div class="performance-detail">
                        <span class="detail-label">Views:</span>
                        <span class="detail-value">${posts.views || 0}</span>
                    </div>
                    <div class="performance-detail">
                        <span class="detail-label">Avg Engagement:</span>
                        <span class="detail-value">${posts.engagementRate?.toFixed(1) || 0}%</span>
                    </div>
                </div>
            </div>
        </div>
        <div class="performance-summary">
            <div class="summary-item">
                <span class="summary-label">Avg Processing Time:</span>
                <span class="summary-value">${Math.round(performance.averageProcessingTime / 1000) || 0}s</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Avg Retry Count:</span>
                <span class="summary-value">${performance.averageRetryCount?.toFixed(1) || 0}</span>
            </div>
        </div>
    `;
}

function updateAccountComparison(accounts) {
    if (!accounts || accounts.length === 0) return;

    const container = document.getElementById('account-comparison');
    if (!container) return;

    container.innerHTML = `
        <div class="account-comparison">
            <table class="account-comparison-table">
                <thead>
                    <tr>
                        <th>Account</th>
                        <th>Page</th>
                        <th>Uploads</th>
                        <th>Success Rate</th>
                        <th>Total Views</th>
                        <th>Avg Engagement</th>
                        <th>Processing Time</th>
                    </tr>
                </thead>
                <tbody>
                    ${accounts.map(account => `
                        <tr>
                            <td>${account.accountName}</td>
                            <td>${account.pageName || account.pageId || 'N/A'}</td>
                            <td>${account.totalUploads}</td>
                            <td>${account.successRate?.toFixed(1) || 0}%</td>
                            <td>${account.totalViews || 0}</td>
                            <td>${account.averageEngagementRate?.toFixed(1) || 0}%</td>
                            <td>${Math.round(account.averageProcessingTime / 1000) || 0}s</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}



function updateCategoryPerformance(categories) {
    if (!categories || categories.length === 0) return;

    const container = document.getElementById('category-performance');
    if (!container) return;

    container.innerHTML = `
        <div class="category-performance">
            ${categories.map(category => `
                <div class="category-card">
                    <h4>${category.category.charAt(0).toUpperCase() + category.category.slice(1)}</h4>
                    <div class="category-stats">
                        <div>
                            <span class="category-stat-label">Uploads:</span>
                            <span class="category-stat-value">${category.totalUploads}</span>
                        </div>
                        <div>
                            <span class="category-stat-label">Avg Views:</span>
                            <span class="category-stat-value">${Math.round(category.averageViews || 0)}</span>
                        </div>
                    </div>
                    <div class="category-stats">
                        <div>
                            <span class="category-stat-label">Engagement:</span>
                            <span class="category-stat-value">${category.averageEngagementRate?.toFixed(1) || 0}%</span>
                        </div>
                    </div>
                    ${category.topHashtags && category.topHashtags.length > 0 ? `
                        <div class="category-hashtags">
                            ${category.topHashtags.slice(0, 5).map(tag => `
                                <span class="category-hashtag">#${tag}</span>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>
    `;
}

function updateTrendsChart(trends) {
    if (!trends || !trends.dailyStats || trends.dailyStats.length === 0) return;

    const container = document.getElementById('trends-chart');
    if (!container) return;

    // Simple chart placeholder - in real implementation, you would use a charting library
    const recentDays = trends.dailyStats.slice(-7); // Last 7 days

    container.innerHTML = `
        <div class="trends-chart">
            <div class="chart-placeholder">
                <i class="fas fa-chart-line"></i>
                <h4>Upload Trends (Last 7 Days)</h4>
                <div class="trends-summary">
                    <div class="trend-item">
                        <span class="trend-label">Total Uploads:</span>
                        <span class="trend-value">${recentDays.reduce((sum, day) => sum + day.totalUploads, 0)}</span>
                    </div>
                    <div class="trend-item">
                        <span class="trend-label">Total Views:</span>
                        <span class="trend-value">${recentDays.reduce((sum, day) => sum + day.totalViews, 0)}</span>
                    </div>
                    <div class="trend-item">
                        <span class="trend-label">Total Engagement:</span>
                        <span class="trend-value">${recentDays.reduce((sum, day) => sum + day.totalEngagement, 0)}</span>
                    </div>
                </div>
                <p class="chart-note">Chart visualization akan diimplementasikan dengan library seperti Chart.js</p>
            </div>
        </div>
    `;
}

// Event listeners for analytics
function setupAnalyticsEventListeners() {
    // User filter selector
    const userFilterSelect = document.getElementById('user-filter-select');
    if (userFilterSelect) {
        userFilterSelect.addEventListener('change', (e) => {
            analyticsState.currentUserFilter = e.target.value;
            loadAnalyticsData();
        });
    }

    // Time range selector
    const timeRangeSelect = document.getElementById('time-range-select');
    if (timeRangeSelect) {
        timeRangeSelect.addEventListener('change', (e) => {
            analyticsState.currentTimeRange = e.target.value;
            loadAnalyticsData();
        });
    }

    // Refresh button
    const refreshBtn = document.getElementById('refresh-analytics-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadAnalyticsData();
        });
    }

    // Export button
    const exportBtn = document.getElementById('export-analytics-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            try {
                exportBtn.disabled = true;
                exportBtn.innerHTML = '<div class="loading"></div> Exporting...';

                const result = await fetch(`${API_BASE}/api/analytics/export`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        format: 'json',
                        timeRange: analyticsState.currentTimeRange,
                        userId: analyticsState.currentUserFilter
                    })
                });
                const response = await result.json();

                if (response.success) {
                    // Create download link
                    const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `analytics-${analyticsState.currentTimeRange}-${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);

                    showToast('Analytics berhasil diekspor', 'success');
                } else {
                    showToast(`Export gagal: ${response.error}`, 'error');
                }
            } catch (error) {
                showToast(`Export error: ${error.message}`, 'error');
            } finally {
                exportBtn.disabled = false;
                exportBtn.innerHTML = '<i class="fas fa-download"></i> Export';
            }
        });
    }
}

// Initialize analytics event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Setup analytics event listeners after a short delay to ensure all elements are ready
    setTimeout(() => {
        setupAnalyticsEventListeners();
    }, 500);
});

// Analytics tracking functions
async function trackUploadToAnalytics(formData, queueId) {
    try {
        // Get account data untuk page info
        const selectedAccount = appState.accounts.find(acc => acc.name === formData.account);
        if (!selectedAccount) {
            console.log('Account not found for analytics tracking');
            return;
        }

        const pageInfo = selectedAccount.pages?.find(p => p.id === formData.page);

        const uploadData = {
            id: queueId,
            accountName: formData.account,
            pageId: formData.page,
            pageName: pageInfo?.name || formData.page,
            type: formData.type,
            fileName: formData.file ? formData.file.split(/[/\\]/).pop() : 'unknown',
            caption: formData.caption,
            hashtags: extractHashtags(formData.caption),
            status: 'pending',
            scheduledTime: formData.schedule,
            category: categorizeContent(formData),
            priority: 'medium'
        };

        const result = await fetch(`${API_BASE}/api/analytics/track-upload`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(uploadData)
        });
        const response = await result.json();

        if (response.success) {
            console.log(`📊 Upload tracked to analytics: ${queueId}`);
        } else {
            console.error('Error tracking upload to analytics:', response.error);
        }
    } catch (error) {
        console.error('Error tracking upload to analytics:', error);
    }
}

function extractHashtags(caption) {
    if (!caption) return [];

    const hashtagRegex = /#[\w]+/g;
    const matches = caption.match(hashtagRegex);
    return matches ? matches.map(tag => tag.substring(1)) : [];
}

// Edit Queue Modal Functions
function openEditQueueModal(item) {
    // Set the item ID
    elements.editQueueId.value = item.id;
    elements.editQueueModalTitle.textContent = `Edit Item Antrian - ${item.id}`;

    // Populate account select
    elements.editAccountSelect.innerHTML = '<option value="">-- Pilih Akun --</option>' +
        appState.accounts.map(account => {
            const selected = account.name === item.account ? 'selected' : '';
            return `<option value="${account.name}" ${selected}>${account.name}</option>`;
        }).join('');

    // Populate page select based on selected account
    updateEditPageSelect();
    elements.editPageSelect.value = item.page || '';

    // Set upload type (reel or post)
    const uploadTypeRadios = elements.editUploadType;
    uploadTypeRadios.forEach(radio => {
        if (radio.value === item.type) {
            radio.checked = true;
        }
    });

    // Set caption and other fields
    elements.editCaption.value = item.caption || '';
    elements.editCaptionLanguage.value = 'indonesia'; // Default

    // Set schedule time
    if (item.schedule) {
        // Convert ISO string to datetime-local format (YYYY-MM-DDTHH:MM)
        const scheduleDate = new Date(item.schedule);
        const year = scheduleDate.getFullYear();
        const month = String(scheduleDate.getMonth() + 1).padStart(2, '0');
        const day = String(scheduleDate.getDate()).padStart(2, '0');
        const hours = String(scheduleDate.getHours()).padStart(2, '0');
        const minutes = String(scheduleDate.getMinutes()).padStart(2, '0');
        elements.editScheduleTime.value = `${year}-${month}-${day}T${hours}:${minutes}`;
    } else {
        // Set default to current date/time in YYYY-MM-DDTHH:MM format
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        elements.editScheduleTime.value = `${year}-${month}-${day}T${hours}:${minutes}`;
    }

    // Set status
    elements.editQueueStatus.value = item.status || 'pending';

    // Show/hide retry count group based on status
    toggleRetryCountGroup();
    elements.editRetryCount.value = item.attempts || 0;

    // Clear any existing error messages
    showToast('Edit modal siap digunakan', 'info');

    // Show modal
    elements.editQueueModal.classList.add('show');
}

function closeEditQueueModal() {
    elements.editQueueModal.classList.remove('show');
    elements.editQueueForm.reset();
    elements.editAccountSelect.innerHTML = '<option value="">-- Pilih Akun --</option>';
    elements.editPageSelect.innerHTML = '<option value="">-- Pilih Halaman --</option>';
}

async function updateEditPageSelect() {
    const selectedAccountName = elements.editAccountSelect.value;
    const selectedAccount = appState.accounts.find(acc => acc.name === selectedAccountName);

    if (selectedAccount && selectedAccount.pages) {
        elements.editPageSelect.innerHTML = '<option value="">-- Pilih Halaman --</option>' +
            selectedAccount.pages.map(page => `<option value="${page.id}">${page.name}</option>`).join('');
        elements.editPageSelect.disabled = false;
    } else {
        elements.editPageSelect.innerHTML = '<option value="">-- Pilih Halaman --</option>';
        elements.editPageSelect.disabled = true;
    }
}

function toggleRetryCountGroup() {
    const selectedStatus = elements.editQueueStatus.value;
    const retryCountGroup = elements.retryCountGroup;

    // Show retry count only for retry status
    if (selectedStatus === 'retry') {
        retryCountGroup.style.display = 'block';
    } else {
        retryCountGroup.style.display = 'none';
    }
}

async function generateCaptionForEdit() {
    const fileName = elements.editCaption.value || 'video';
    const language = elements.editCaptionLanguage.value;

    if (!fileName) {
        showToast('Tidak ada nama file untuk generate caption', 'warning');
        return;
    }

    try {
        elements.editGenerateCaptionBtn.disabled = true;
        elements.editGenerateCaptionBtn.innerHTML = '<div class="loading"></div> Generating...';

        // Call Gemini service through API
        const result = await fetch(`${API_BASE}/api/gemini/generate-caption`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ fileName, language })
        });
        const response = await result.json();

        if (response.success) {
            elements.editCaption.value = response.description || '';
            showToast('Caption berhasil digenerate untuk edit!', 'success');
        } else {
            showToast(`Gagal generate caption: ${response.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        elements.editGenerateCaptionBtn.disabled = false;
        elements.editGenerateCaptionBtn.innerHTML = '<i class="fas fa-magic"></i> Generate Caption';
    }
}

async function saveEditQueueItem(e) {
    e.preventDefault();

    const itemId = elements.editQueueId.value;
    const updates = {
        accountName: elements.editAccountSelect.value,
        pageId: elements.editPageSelect.value,
        type: document.querySelector('input[name="edit-upload-type"]:checked')?.value || 'reel',
        caption: elements.editCaption.value.trim(),
        schedule: elements.editScheduleTime.value ? new Date(elements.editScheduleTime.value).toISOString() : null,
        status: elements.editQueueStatus.value
    };

    // Add retry count if status is retry
    if (updates.status === 'retry') {
        const retryCount = parseInt(elements.editRetryCount.value) || 0;
        updates.attempts = retryCount;

        // Calculate next retry time (1 minute * attempt count)
        const retryDelay = retryCount * 60000; // 1 minute per attempt
        updates.nextRetry = new Date(Date.now() + retryDelay).toISOString();
    } else {
        // Clear next retry if not retry status
        updates.nextRetry = null;
        updates.lastError = null;
    }

    // Validate required fields
    if (!updates.accountName || !updates.pageId) {
        showToast('Akun dan halaman harus dipilih', 'error');
        return;
    }

    try {
        elements.saveEditQueueBtn.disabled = true;
        elements.saveEditQueueBtn.innerHTML = '<div class="loading"></div> Menyimpan...';

        const response = await fetch(`${API_BASE}/api/queue/${itemId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updates)
        });
        const result = await response.json();

        if (result.success) {
            closeEditQueueModal();
            await loadAppData(); // Refresh the queue display
            showToast('Item antrian berhasil diupdate!', 'success');
        } else {
            showToast(`Gagal mengupdate item: ${result.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error memperbaharui item: ${error.message}`, 'error');
    } finally {
        elements.saveEditQueueBtn.disabled = false;
        elements.saveEditQueueBtn.innerHTML = '<i class="fas fa-save"></i> Simpan Perubahan';
    }
}

// Handle modal click outside for edit queue modal
elements.editQueueModal?.addEventListener('click', (e) => {
    if (e.target === elements.editQueueModal) {
        closeEditQueueModal();
    }
});

        // Handle escape key for modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && elements.accountModal.classList.contains('show')) {
                closeAccountModal();
            }
            if (e.key === 'Escape' && elements.geminiModal.classList.contains('show')) {
                closeGeminiModal();
            }
            if (e.key === 'Escape' && elements.editQueueModal.classList.contains('show')) {
                closeEditQueueModal();
            }
            if (e.key === 'Escape' && elements.userModal.classList.contains('show')) {
                closeUserModal();
            }
        });

function categorizeContent(formData) {
    const text = `${formData.caption || ''} ${formData.hashtags?.join(' ') || ''}`.toLowerCase();

    if (text.includes('tutorial') || text.includes('how to') || text.includes('learn') || text.includes('education')) {
        return 'education';
    } else if (text.includes('promo') || text.includes('discount') || text.includes('sale') || text.includes('product')) {
        return 'promotional';
    } else if (text.includes('funny') || text.includes('comedy') || text.includes('entertainment') || text.includes('viral')) {
        return 'entertainment';
    } else if (text.includes('news') || text.includes('update') || text.includes('information')) {
        return 'news';
    } else {
        return 'general';
    }
}

// Debug Tab Functions
async function loadDebugData() {
    try {
        // Load latest screenshots
        await refreshScreenshots();

        // Start real-time log streaming
        startTerminalLogStreaming();

        showToast('Debug data berhasil dimuat', 'info');
    } catch (error) {
        showToast(`Gagal memuat debug data: ${error.message}`, 'error');
    }
}

async function refreshScreenshots() {
    try {
        elements.refreshScreenshotsBtn.disabled = true;
        elements.refreshScreenshotsBtn.innerHTML = '<div class="loading"></div> Loading...';

        const result = await fetch(`${API_BASE}/api/debug/screenshots`);
        const response = await result.json();

        if (response.success) {
            updateScreenshotsGallery(response.screenshots);
            showToast('Screenshot berhasil diperbaharui', 'success');
        } else {
            updateScreenshotsGallery([]);
            showToast(`Gagal memperbaharui screenshot: ${response.error}`, 'error');
        }
    } catch (error) {
        updateScreenshotsGallery([]);
        showToast(`Error memperbaharui screenshot: ${error.message}`, 'error');
    } finally {
        elements.refreshScreenshotsBtn.disabled = false;
        elements.refreshScreenshotsBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh Screenshots';
    }
}

function updateScreenshotsGallery(screenshots) {
    const gallery = elements.screenshotsGallery;
    if (!gallery) return;

    if (!screenshots || screenshots.length === 0) {
        gallery.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-camera"></i>
                <h3>Belum ada screenshot</h3>
                <p>Screenshot debug akan muncul di sini saat proses upload sedang berjalan.</p>
            </div>
        `;
        return;
    }

    gallery.innerHTML = screenshots.map(screenshot => `
        <div class="debug-screenshot">
            <div class="screenshot-info">
                <h4>${screenshot.step || 'Screenshot'}</h4>
                <small>${new Date(screenshot.timestamp).toLocaleString()}</small>
            </div>
            <img src="${API_BASE}/api/debug/screenshots/${screenshot.filename}?t=${Date.now()}"
                 alt="${screenshot.step}"
                 onclick="openScreenshotModal('${screenshot.filename}', '${screenshot.step || 'Screenshot'}')"
                 style="max-width: 100%; cursor: pointer; border-radius: 8px;">
            <div class="screenshot-actions">
                <button onclick="downloadScreenshot('${screenshot.filename}')" class="btn-secondary btn-small">
                    <i class="fas fa-download"></i> Download
                </button>
            </div>
        </div>
    `).join('');
}

let logStreamingInterval = null;
let currentLogType = 'stdout';

function startTerminalLogStreaming() {
    // Clear existing interval if any
    if (logStreamingInterval) {
        clearInterval(logStreamingInterval);
    }

    // Initial load
    updateTerminalLogs();

    // Set up polling every 2 seconds
    logStreamingInterval = setInterval(async () => {
        try {
            await updateTerminalLogs();
        } catch (error) {
            console.error('Error updating terminal logs:', error);
        }
    }, 2000);
}

async function updateTerminalLogs() {
    if (!elements.terminalOutput) return;

    try {
        const limit = 50; // Last 50 lines
        const result = await fetch(`${API_BASE}/api/debug/logs?type=${currentLogType}&limit=${limit}`);
        const response = await result.json();

        if (response.success) {
            const logs = response.logs || [];
            elements.terminalOutput.innerHTML = logs.length > 0
                ? logs.map(line => `<div class="terminal-line">${escapeHtml(line)}</div>`).join('')
                : '<div class="terminal-line">No logs available yet...</div>';

            // Scroll to bottom
            elements.terminalOutput.scrollTop = elements.terminalOutput.scrollHeight;
        }
    } catch (error) {
        console.error('Error fetching terminal logs:', error);
        elements.terminalOutput.innerHTML = '<div class="terminal-line">Unable to fetch logs...</div>';
    }
}

function setupTerminalTabSwitching() {
    const terminalTabs = document.querySelectorAll('.terminal-tab');
    terminalTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Update active tab
            terminalTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update log type
            currentLogType = tab.dataset.tab;

            // Refresh logs with new type
            if (logStreamingInterval) {
                clearInterval(logStreamingInterval);
            }
            startTerminalLogStreaming();
        });
    });
}

async function clearTerminalLogs() {
    try {
        elements.clearTerminalLogsBtn.disabled = true;
        elements.clearTerminalLogsBtn.innerHTML = '<div class="loading"></div> Clearing...';

        const result = await fetch(`${API_BASE}/api/debug/logs/clear`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ type: currentLogType })
        });
        const response = await result.json();

        if (response.success) {
            // Clear local logs and restart streaming
            if (elements.terminalOutput) {
                elements.terminalOutput.innerHTML = '<div class="terminal-line">Logs cleared...</div>';
            }
            showToast('Terminal logs berhasil dibersihkan', 'success');
        } else {
            showToast(`Gagal membersihkan logs: ${response.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error membersihkan logs: ${error.message}`, 'error');
    } finally {
        elements.clearTerminalLogsBtn.disabled = false;
        elements.clearTerminalLogsBtn.innerHTML = '<i class="fas fa-trash"></i> Clear Terminal Logs';
    }
}

// Utility functions for debug
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Make debug functions globally available
window.openScreenshotModal = function(filename, step) {
    // Create a modal to show full-size screenshot
    const modal = document.createElement('div');
    modal.className = 'screenshot-modal';
    modal.innerHTML = `
        <div class="screenshot-modal-content">
            <div class="screenshot-modal-header">
                <h3>${step}</h3>
                <button class="screenshot-modal-close" onclick="this.closest('.screenshot-modal').remove()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="screenshot-modal-body">
                <img src="${API_BASE}/api/debug/screenshots/${filename}" alt="${step}">
            </div>
        </div>
    `;
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });
    document.body.appendChild(modal);
};

// Login and Registration Functions
async function switchLoginTab(tabName) {
    // Update tab buttons
    elements.loginTabBtn.classList.toggle('active', tabName === 'login');
    elements.registerTabBtn.classList.toggle('active', tabName === 'register');

    // Show/hide forms
    if (elements.loginTab) {
        elements.loginTab.style.display = tabName === 'login' ? 'block' : 'none';
    }
    if (elements.registerTab) {
        elements.registerTab.style.display = tabName === 'register' ? 'block' : 'none';
    }

    // Hide any messages
    if (elements.loginMessage) {
        elements.loginMessage.classList.remove('show-message');
    }

    // Clear forms
    if (tabName === 'login' && elements.loginForm) {
        elements.loginForm.reset();
    } else if (tabName === 'register') {
        // Note: Register form elements might be added later in HTML
        if (elements.registerUsername) elements.registerUsername.value = '';
        if (elements.registerPassword) elements.registerPassword.value = '';
        if (elements.registerPasswordConfirm) elements.registerPasswordConfirm.value = '';
        if (elements.registerDisplayName) elements.registerDisplayName.value = '';
    }
}

async function handleLoginSubmit(e) {
    e.preventDefault();

    const username = elements.loginUsername?.value?.trim();
    const password = elements.loginPassword?.value;

    if (!username || !password) {
        showLoginMessage('Mohon lengkapi semua field', 'warning');
        return;
    }

    try {
        elements.loginBtn.disabled = true;
        elements.loginBtn.innerHTML = '<div class="loading"></div> Masuk...';

        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (result.success) {
            appState.user = result.user;
            appState.isAuthenticated = true;
            showApp();
            updateUserInfo();
            await loadAppData();
            setupNavigation();
            updateStatusBar();
            showToast(`Selamat datang kembali, ${result.user.displayName || result.user.username}!`, 'success');
        } else {
            showLoginMessage(result.error || 'Login gagal', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showLoginMessage('Terjadi kesalahan saat login', 'error');
    } finally {
        elements.loginBtn.disabled = false;
        elements.loginBtn.innerHTML = 'Masuk';
    }
}

async function handleRegister(e) {
    e.preventDefault();

    const username = elements.registerUsername?.value?.trim();
    const password = elements.registerPassword?.value;
    const passwordConfirm = elements.registerPasswordConfirm?.value;
    const displayName = elements.registerDisplayName?.value?.trim();

    if (!username || !password || !displayName) {
        showLoginMessage('Mohon lengkapi semua field', 'warning');
        return;
    }

    if (password !== passwordConfirm) {
        showLoginMessage('Password tidak cocok', 'error');
        return;
    }

    if (password.length < 6) {
        showLoginMessage('Password minimal 6 karakter', 'warning');
        return;
    }

    try {
        elements.registerBtn.disabled = true;
        elements.registerBtn.innerHTML = '<div class="loading"></div> Daftar...';

        const response = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, displayName })
        });

        const result = await response.json();

        if (result.success) {
            appState.user = result.user;
            appState.isAuthenticated = true;
            showApp();
            await loadAppData();
            setupNavigation();
            updateStatusBar();
            showToast(`Selamat datang, ${result.user.displayName}! Akun berhasil dibuat.`, 'success');
        } else {
            showLoginMessage(result.error || 'Registrasi gagal', 'error');
        }
    } catch (error) {
        console.error('Register error:', error);
        showLoginMessage('Terjadi kesalahan saat registrasi', 'error');
    } finally {
        elements.registerBtn.disabled = false;
        elements.registerBtn.innerHTML = 'Daftar';
    }
}

function showLoginMessage(message, type = 'error') {
    if (!elements.loginMessage) return;

    elements.loginMessage.textContent = message;
    elements.loginMessage.className = `login-message ${type} show-message`;
}

// Update user info display in header
function updateUserInfo() {
    if (appState.user) {
        if (elements.userDisplayName) {
            elements.userDisplayName.textContent = appState.user.displayName || appState.user.username || 'User';
        }
        if (elements.userInfo) {
            elements.userInfo.style.display = 'flex';
        }
        if (elements.logoutBtn) {
            elements.logoutBtn.style.display = 'block';
        }
    } else {
        if (elements.userDisplayName) {
            elements.userDisplayName.textContent = '';
        }
        if (elements.userInfo) {
            elements.userInfo.style.display = 'none';
        }
        if (elements.logoutBtn) {
            elements.logoutBtn.style.display = 'none';
        }
    }
}

// Logout function (can be called from UI)
async function handleLogout(e) {
    if (e) e.preventDefault();

    const confirmLogout = confirm('Apakah Anda yakin ingin logout?');
    if (!confirmLogout) return;

    try {
        const response = await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST'
        });
        const result = await response.json();

        if (result.success) {
            appState.user = null;
            appState.isAuthenticated = false;
            appState.accounts = [];
            appState.uploadQueue = [];

            showLogin();
            showToast('Anda telah berhasil logout', 'info');
        } else {
            // Still logout from client side even if server fails
            appState.user = null;
            appState.isAuthenticated = false;
            showLogin();
            showToast('Logout berhasil (client-side)', 'info');
        }
    } catch (error) {
        console.error('Logout error:', error);
        // Force logout on client side even if server fails
        appState.user = null;
        appState.isAuthenticated = false;
        showLogin();
        showToast('Logout berhasil (client-side)', 'info');
    }
}

// Change password function
async function handleChangePassword(e) {
    e.preventDefault();

    const currentPassword = elements.currentPassword?.value?.trim();
    const newPassword = elements.newPassword?.value?.trim();
    const confirmNewPassword = elements.confirmNewPassword?.value?.trim();

    if (!currentPassword) {
        showToast('Password saat ini harus diisi', 'error');
        return;
    }

    if (!newPassword || newPassword.length < 6) {
        showToast('Password baru minimal 6 karakter', 'error');
        return;
    }

    if (newPassword !== confirmNewPassword) {
        showToast('Konfirmasi password baru tidak cocok', 'error');
        return;
    }

    if (currentPassword === newPassword) {
        showToast('Password baru harus berbeda dengan password saat ini', 'warning');
        return;
    }

    try {
        elements.changePasswordForm.querySelector('button[type="submit"]').disabled = true;
        elements.changePasswordForm.querySelector('button[type="submit"]').innerHTML = '<div class="loading"></div> Mengubah...';

        const response = await fetch(`${API_BASE}/auth/change-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                currentPassword,
                newPassword
            })
        });

        const result = await response.json();

        if (result.success) {
            elements.changePasswordForm.reset();
            showToast('Password berhasil diubah', 'success');
        } else {
            showToast(result.error || 'Gagal mengubah password', 'error');
        }
    } catch (error) {
        console.error('Change password error:', error);
        showToast('Terjadi kesalahan saat mengubah password', 'error');
    } finally {
        elements.changePasswordForm.querySelector('button[type="submit"]').disabled = false;
        elements.changePasswordForm.querySelector('button[type="submit"]').innerHTML = '<i class="fas fa-save"></i> Ubah Password';
    }
}

window.downloadScreenshot = async function(filename) {
    try {
        const response = await fetch(`${API_BASE}/api/debug/screenshots/${filename}`);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Screenshot berhasil didownload', 'success');
    } catch (error) {
        showToast(`Gagal download screenshot: ${error.message}`, 'error');
    }
};

// Admin Functions
async function loadAdminData() {
    try {
        adminState.isLoading = true;

        // Load users data
        const usersResponse = await fetch(`${API_BASE}/api/admin/users`);
        const usersResult = await usersResponse.json();

        if (usersResult.success) {
            adminState.users = usersResult.users || [];
            updateUsersDisplay();

            // Update stats
            elements.totalUsers.textContent = adminState.users.length;
            elements.activeUsers.textContent = adminState.users.filter(u => u.lastLogin && Date.now() - new Date(u.lastLogin) < 24 * 60 * 60 * 1000).length; // Active in last 24h
            elements.totalQueues.textContent = appState.uploadQueue.length;

            showToast('Admin data berhasil dimuat', 'success');
        } else {
            showToast(`Gagal memuat data admin: ${usersResult.error}`, 'error');
            updateUsersDisplay(); // Show empty
        }
    } catch (error) {
        console.error('Admin data load error:', error);
        showToast(`Error memuat data admin: ${error.message}`, 'error');
        updateUsersDisplay(); // Show empty
    } finally {
        adminState.isLoading = false;
    }
}

function updateUsersDisplay() {
    if (!elements.userTableBody) return;

    if (adminState.users.length === 0) {
        if (elements.userEmptyState) elements.userEmptyState.style.display = 'block';
        return;
    }

    if (elements.userEmptyState) elements.userEmptyState.style.display = 'none';

    elements.userTableBody.innerHTML = adminState.users.map(user => `
        <tr>
            <td>${user.username}</td>
            <td>${user.displayName}</td>
            <td>
                <span class="role-badge ${user.role}">${user.role}</span>
            </td>
            <td>${new Date(user.createdAt).toLocaleDateString()}</td>
            <td>${user.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'Belum pernah login'}</td>
            <td class="user-actions">
                <button class="btn-secondary btn-small" onclick="editUser('${user.id}')">
                    <i class="fas fa-edit"></i> Edit
                </button>
                <button class="btn-danger btn-small" onclick="deleteUser('${user.id}', '${user.username}')">
                    <i class="fas fa-trash"></i> Hapus
                </button>
            </td>
        </tr>
    `).join('');
}

function openUserModal(user = null) {
    adminState.currentEditingUser = user;

    if (user) {
        // Edit mode
        elements.userModalTitle.textContent = 'Edit User';
        elements.userId.value = user.id;
        elements.userUsername.value = user.username;
        elements.userDisplayName.value = user.displayName;
        elements.userRole.value = user.role || 'user';
        elements.userPassword.value = ''; // Don't show password
        elements.userConfirmPassword.value = '';
        elements.saveUserBtn.innerHTML = '<i class="fas fa-save"></i> Update User';

        // Make username readonly for edit
        elements.userUsername.readOnly = true;
        elements.userUsername.style.opacity = '0.7';

        // Hide password fields for edit
        elements.userPassword.closest('.form-group').style.display = 'none';
        elements.userConfirmPassword.closest('.form-group').style.display = 'none';
    } else {
        // Add mode
        elements.userModalTitle.textContent = 'Tambah User Baru';
        elements.userForm.reset();
        elements.userId.value = '';
        elements.saveUserBtn.innerHTML = '<i class="fas fa-save"></i> Simpan User';

        // Make username editable
        elements.userUsername.readOnly = false;
        elements.userUsername.style.opacity = '1';

        // Show password fields
        elements.userPassword.closest('.form-group').style.display = 'block';
        elements.userConfirmPassword.closest('.form-group').style.display = 'block';
    }

    elements.userModal.classList.add('show');
}

function closeUserModal() {
    elements.userModal.classList.remove('show');
    elements.userForm.reset();
    adminState.currentEditingUser = null;
}

async function handleSaveUser(e) {
    e.preventDefault();

    console.log('handleSaveUser called');

    // Check if required elements exist
    if (!elements.userId || !elements.userUsername || !elements.userRole) {
        console.error('Required elements missing:', {
            userId: !!elements.userId,
            userUsername: !!elements.userUsername,
            userRole: !!elements.userRole
        });
        showToast('Form belum siap. Silakan coba lagi.', 'error');
        return;
    }

    // Force immediate value capture before any processing
    // This should capture current user input regardless of focus state
    const rawUsername = document.getElementById('user-username')?.value || '';
    const rawDisplayName = document.getElementById('user-display-name')?.value || '';
    const rawPassword = document.getElementById('user-password')?.value || '';
    const rawConfirmPassword = document.getElementById('user-confirm-password')?.value || '';
    const rawRole = document.getElementById('user-role')?.value || '';

    console.log('Raw DOM values at submit:', { rawUsername, rawDisplayName, rawPassword, rawConfirmPassword, rawRole });

    // Force blur/focus cycle to trigger any pending value updates
    const inputIds = ['user-username', 'user-display-name', 'user-password', 'user-confirm-password'];
    inputIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.focus();
            el.blur();
        }
    });

    // Small delay for any event handlers
    await new Promise(resolve => setTimeout(resolve, 50));

    // Get final values after potential updates
    const userId = document.getElementById('user-id')?.value?.trim() || '';
    const username = document.getElementById('user-username')?.value?.trim() || rawUsername.trim();
    const password = document.getElementById('user-password')?.value?.trim() || rawPassword.trim();
    const confirmPassword = document.getElementById('user-confirm-password')?.value?.trim() || rawConfirmPassword.trim();
    const role = document.getElementById('user-role')?.value || rawRole;

    // Display name is automatically set to username
    const displayName = username;

    console.log('Final processed values:', { userId, username, displayName, password: password ? '[REDACTED]' : '', confirmPassword: confirmPassword ? '[REDACTED]' : '', role });

    // Basic validation with specific field checking
    console.log('Validation check:', { username: !!username, role: !!role });

    if (!username) {
        showToast('Username harus diisi', 'error');
        elements.userUsername?.focus();
        return;
    }

    if (!role) {
        showToast('Role harus dipilih', 'error');
        elements.userRole?.focus();
        return;
    }

    let isEdit = !!userId;

    if (!isEdit && (!password || !confirmPassword)) {
        showToast('Password dan konfirmasi password harus diisi', 'error');
        return;
    }

    if (!isEdit && password !== confirmPassword) {
        showToast('Password dan konfirmasi password tidak cocok', 'error');
        return;
    }

    if (!isEdit && password.length < 6) {
        showToast('Password minimal 6 karakter', 'error');
        return;
    }

    // Check if username already exists - always fetch fresh data from server
    console.log('Validating username uniqueness...');
    try {
        const usersResponse = await fetch(`${API_BASE}/api/admin/users`);
        const usersResult = await usersResponse.json();
        if (usersResult.success) {
            const allUsers = usersResult.users || [];
            console.log('Loaded users for validation:', allUsers.map(u => ({ id: u.id, username: u.username })));

            // Check for existing username (case-insensitive)
            const existingUser = allUsers.find(u =>
                u.username.toLowerCase() === username.toLowerCase() &&
                (!isEdit || u.id !== userId)
            );

            if (existingUser) {
                console.log('Username validation failed - existing user:', existingUser);
                showToast(`Username "${username}" sudah digunakan. Silakan pilih username lain.`, 'error');
                elements.userUsername?.focus();
                return;
            }

            console.log('Username validation passed');
        } else {
            console.error('Failed to load users for validation:', usersResult.error);
            // Continue with submission if we can't validate - let server handle it
        }
    } catch (error) {
        console.error('Error loading admin data for validation:', error);
        // Continue with submission if we can't validate - let server handle it
    }

    const userData = {
        username,
        displayName,
        role
    };

    if (!isEdit) {
        userData.password = password;
    }

    try {
        elements.saveUserBtn.disabled = true;
        elements.saveUserBtn.innerHTML = '<div class="loading"></div> Menyimpan...';

        const method = isEdit ? 'PUT' : 'POST';
        const url = isEdit ? `${API_BASE}/api/admin/users/${userId}` : `${API_BASE}/api/admin/users`;

        const response = await fetch(url, {
            method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });

        const result = await response.json();

        if (result.success) {
            closeUserModal();
            await loadAdminData(); // Refresh the users list

            const message = isEdit ?
                'User berhasil diupdate!' :
                `User "${username}" berhasil dibuat dengan role "${role}"!`;

            showToast(message, 'success');

            // If new admin user created, refresh navigation to show admin tab if applicable
            if (role === 'admin') {
                setupNavigation();
            }
        } else {
            showToast(`Gagal menyimpan user: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Save user error:', error);
        showToast(`Error menyimpan user: ${error.message}`, 'error');
    } finally {
        elements.saveUserBtn.disabled = false;
        elements.saveUserBtn.innerHTML = '<i class="fas fa-save"></i> Simpan User';
    }
}

// Make admin functions globally available
window.editUser = async function(userId) {
    const user = adminState.users.find(u => u.id === userId);
    if (user) {
        openUserModal(user);
    } else {
        showToast('User tidak ditemukan', 'error');
    }
};

window.deleteUser = async function(userId, username) {
    if (!confirm(`Apakah Anda yakin ingin menghapus user "${username}"?\n\nTindakan ini tidak dapat dibatalkan!`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            await loadAdminData(); // Refresh users list
            showToast(`User "${username}" berhasil dihapus`, 'success');
        } else {
            showToast(`Gagal menghapus user: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Delete user error:', error);
        showToast(`Error menghapus user: ${error.message}`, 'error');
    }
};

// Handle modal click outside for user modal
elements.userModal?.addEventListener('click', (e) => {
    if (e.target === elements.userModal) {
        closeUserModal();
    }
});

async function handleSaveAdminSettings(e) {
    e.preventDefault();

    const newSettings = {
        showBrowser: elements.adminShowBrowser.checked
    };

    try {
        elements.saveAdminSettingsBtn.disabled = true;
        elements.saveAdminSettingsBtn.innerHTML = '<div class="loading"></div> Menyimpan...';

        const result = await fetch(`${API_BASE}/api/admin/settings`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newSettings)
        });
        const response = await result.json();

        if (response.success) {
            showToast('Pengaturan sistem berhasil disimpan', 'success');
        } else {
            showToast(`Gagal menyimpan pengaturan: ${response.error}`, 'error');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        elements.saveAdminSettingsBtn.disabled = false;
        elements.saveAdminSettingsBtn.innerHTML = '<i class="fas fa-save"></i> Simpan Pengaturan Sistem';
    }
}

// Check current user role on page load to show admin tab
document.addEventListener('DOMContentLoaded', async () => {
    // Wait for initial auth check to complete
    setTimeout(() => {
        if (appState.user?.role === 'admin' || appState.user?.username === 'admin') {
            if (elements.adminTab) elements.adminTab.style.display = 'block';
        }
    }, 1000);
});

// Admin accounts management functions
function updateAdminAccountsDisplay(accounts) {
    if (!elements.adminAccountsList || !accounts) return;

    if (accounts.length === 0) {
        elements.adminAccountsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-users"></i>
                <h3>Belum ada akun</h3>
                <p>Semua akun Facebook dari semua user akan muncul di sini.</p>
            </div>
        `;
        return;
    }

    elements.adminAccountsList.innerHTML = accounts.map(account => {
        const ownerInfo = account.ownerUsername === account.ownerDisplayName
            ? account.ownerUsername
            : `${account.ownerDisplayName} (${account.ownerUsername})`;
        const pagesCount = account.pagesCount || account.pages?.length || 0;

        return `
            <div class="admin-account-card">
                <div class="account-info">
                    <h4>${account.name}</h4>
                    <p><i class="fas fa-user"></i> ${ownerInfo}</p>
                    <p><i class="fas fa-globe"></i> Halaman: ${pagesCount} | ${account.type}</p>
                    <p><i class="fas fa-circle ${account.valid ? 'text-success' : 'text-danger'}"></i> ${account.valid ? 'Valid' : 'Tidak Valid'}</p>
                    <small>Dibuat: ${new Date(account.created_at).toLocaleDateString()}</small>
                </div>
                <div class="account-actions">
                    <button class="btn-secondary btn-small" onclick="viewAdminAccountDetails('${account.id}')">
                        <i class="fas fa-eye"></i> Detail
                    </button>
                    <button class="btn-danger btn-small" onclick="deleteAdminAccount('${account.id}', '${account.name}')">
                        <i class="fas fa-trash"></i> Hapus
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

// Make admin account functions globally available
window.viewAdminAccountDetails = async function(accountId) {
    showToast('Fitur detail akun admin akan diimplementasikan', 'info');
};

window.deleteAdminAccount = async function(accountId, accountName) {
    if (!confirm(`Apakah Anda yakin ingin menghapus akun "${accountName}"?\n\nTindakan ini akan menghapus akun dari user tersebut!`)) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/accounts/${accountId}`, {
            method: 'DELETE'
        });
        const result = await response.json();

        if (result.success) {
            await loadAdminData(); // Refresh the admin data including accounts
            showToast(`Akun "${accountName}" berhasil dihapus`, 'success');
        } else {
            showToast(`Gagal menghapus akun: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Delete admin account error:', error);
        showToast(`Error menghapus akun: ${error.message}`, 'error');
    }
};

// Refresh admin data function
async function refreshAdminData() {
    try {
        // Disable the refresh button
        if (elements.refreshAdminDataBtn) {
            elements.refreshAdminDataBtn.disabled = true;
            elements.refreshAdminDataBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
        }

        // Call loadAdminData to refresh all admin data
        await loadAdminData();

        showToast('Admin data berhasil diperbaharui', 'success');
    } catch (error) {
        console.error('Error refreshing admin data:', error);
        showToast(`Gagal memperbaharui data admin: ${error.message}`, 'error');
    } finally {
        // Re-enable the refresh button
        if (elements.refreshAdminDataBtn) {
            elements.refreshAdminDataBtn.disabled = false;
            elements.refreshAdminDataBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh Data';
        }
    }
}

// Bulk Queue Selection Functions
function toggleSelectAll() {
    const selectAllCheckbox = document.getElementById('select-all-queue');
    const itemCheckboxes = document.querySelectorAll('.queue-item-checkbox-input');

    const isChecked = selectAllCheckbox.checked;

    itemCheckboxes.forEach(checkbox => {
        checkbox.checked = isChecked;
    });

    updateBulkActionButtons();
}

function updateBulkActionButtons() {
    const selectedCheckboxes = document.querySelectorAll('.queue-item-checkbox-input:checked');
    const bulkRetryBtn = document.getElementById('bulk-retry-btn');
    const bulkDeleteBtn = document.getElementById('bulk-delete-btn');

    const hasSelection = selectedCheckboxes.length > 0;

    if (bulkRetryBtn) {
        bulkRetryBtn.disabled = !hasSelection;
    }
    if (bulkDeleteBtn) {
        bulkDeleteBtn.disabled = !hasSelection;
    }

    // Update select all checkbox state
    const selectAllCheckbox = document.getElementById('select-all-queue');
    const totalCheckboxes = document.querySelectorAll('.queue-item-checkbox-input').length;

    if (selectAllCheckbox) {
        if (selectedCheckboxes.length === 0) {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = false;
        } else if (selectedCheckboxes.length === totalCheckboxes) {
            selectAllCheckbox.checked = true;
            selectAllCheckbox.indeterminate = false;
        } else {
            selectAllCheckbox.checked = false;
            selectAllCheckbox.indeterminate = true;
        }
    }
}

async function bulkRetrySelected() {
    const selectedCheckboxes = document.querySelectorAll('.queue-item-checkbox-input:checked');

    if (selectedCheckboxes.length === 0) {
        showToast('Tidak ada item yang dipilih', 'warning');
        return;
    }

    const confirmMessage = `Apakah Anda yakin ingin mencoba upload ulang ${selectedCheckboxes.length} item yang dipilih?`;
    if (!confirm(confirmMessage)) {
        return;
    }

    const bulkRetryBtn = document.getElementById('bulk-retry-btn');
    if (bulkRetryBtn) {
        bulkRetryBtn.disabled = true;
        bulkRetryBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Retrying...';
    }

    let successCount = 0;
    let errorCount = 0;

    for (const checkbox of selectedCheckboxes) {
        const itemId = checkbox.value;

        try {
            const response = await fetch(`${API_BASE}/api/queue/${itemId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    status: 'pending',
                    retryCount: 0,
                    errorMessage: null
                })
            });
            const result = await response.json();

            if (result.success) {
                successCount++;
            } else {
                errorCount++;
                console.error(`Failed to retry item ${itemId}:`, result.error);
            }
        } catch (error) {
            errorCount++;
            console.error(`Error retrying item ${itemId}:`, error);
        }
    }

    if (bulkRetryBtn) {
        bulkRetryBtn.disabled = false;
        bulkRetryBtn.innerHTML = '<i class="fas fa-redo"></i> Retry Terpilih';
    }

    // Refresh queue display
    await loadAppData();

    if (successCount > 0) {
        showToast(`${successCount} item berhasil diatur untuk retry`, 'success');
    }
    if (errorCount > 0) {
        showToast(`${errorCount} item gagal diatur untuk retry`, 'warning');
    }
}

async function bulkDeleteSelected() {
    const selectedCheckboxes = document.querySelectorAll('.queue-item-checkbox-input:checked');

    if (selectedCheckboxes.length === 0) {
        showToast('Tidak ada item yang dipilih', 'warning');
        return;
    }

    const confirmMessage = `Apakah Anda yakin ingin menghapus ${selectedCheckboxes.length} item yang dipilih?\n\nTindakan ini tidak dapat dibatalkan!`;
    if (!confirm(confirmMessage)) {
        return;
    }

    const bulkDeleteBtn = document.getElementById('bulk-delete-btn');
    if (bulkDeleteBtn) {
        bulkDeleteBtn.disabled = true;
        bulkDeleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';
    }

    let successCount = 0;
    let errorCount = 0;

    for (const checkbox of selectedCheckboxes) {
        const itemId = checkbox.value;

        try {
            const response = await fetch(`${API_BASE}/api/queue/${itemId}`, {
                method: 'DELETE'
            });
            const result = await response.json();

            if (result.success) {
                successCount++;
            } else {
                errorCount++;
                console.error(`Failed to delete item ${itemId}:`, result.error);
            }
        } catch (error) {
            errorCount++;
            console.error(`Error deleting item ${itemId}:`, error);
        }
    }

    if (bulkDeleteBtn) {
        bulkDeleteBtn.disabled = false;
        bulkDeleteBtn.innerHTML = '<i class="fas fa-trash"></i> Hapus Terpilih';
    }

    // Refresh queue display
    await loadAppData();

    if (successCount > 0) {
        showToast(`${successCount} item berhasil dihapus`, 'success');
    }
    if (errorCount > 0) {
        showToast(`${errorCount} item gagal dihapus`, 'warning');
    }
}

async function bulkDeleteAll() {
    const allItems = appState.uploadQueue;

    if (allItems.length === 0) {
        showToast('Tidak ada item dalam antrian', 'warning');
        return;
    }

    const confirmMessage = `Apakah Anda yakin ingin menghapus SEMUA ${allItems.length} item dalam antrian?\n\nTindakan ini tidak dapat dibatalkan!`;
    if (!confirm(confirmMessage)) {
        return;
    }

    const bulkDeleteAllBtn = document.getElementById('bulk-delete-all-btn');
    if (bulkDeleteAllBtn) {
        bulkDeleteAllBtn.disabled = true;
        bulkDeleteAllBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting All...';
    }

    let successCount = 0;
    let errorCount = 0;

    for (const item of allItems) {
        try {
            const response = await fetch(`${API_BASE}/api/queue/${item.id}`, {
                method: 'DELETE'
            });
            const result = await response.json();

            if (result.success) {
                successCount++;
            } else {
                errorCount++;
                console.error(`Failed to delete item ${item.id}:`, result.error);
            }
        } catch (error) {
            errorCount++;
            console.error(`Error deleting item ${item.id}:`, error);
        }
    }

    if (bulkDeleteAllBtn) {
        bulkDeleteAllBtn.disabled = false;
        bulkDeleteAllBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Hapus Semua';
    }

    // Refresh queue display
    await loadAppData();

    if (successCount > 0) {
        showToast(`${successCount} item berhasil dihapus dari antrian`, 'success');
    }
    if (errorCount > 0) {
        showToast(`${errorCount} item gagal dihapus`, 'warning');
    }
}

// Update loadAdminData to load admin settings and admin accounts
const originalLoadAdminData = loadAdminData;
loadAdminData = async function() {
    // Call the original function first to load users
    await originalLoadAdminData();

    try {
        // Load admin settings
        const settingsResponse = await fetch(`${API_BASE}/api/admin/settings`);
        const settingsResult = await settingsResponse.json();

        if (settingsResult.success) {
            const adminSettings = settingsResult.settings || {};
            // Update the admin form with current settings
            if (elements.adminShowBrowser) {
                elements.adminShowBrowser.checked = adminSettings.showBrowser || false;
            }
        }

        // Load admin accounts data (accounts from all users)
        const accountsResponse = await fetch(`${API_BASE}/api/admin/accounts`);
        const accountsResult = await accountsResponse.json();

        if (accountsResult.success) {
            updateAdminAccountsDisplay(accountsResult.accounts || []);
            elements.totalAccounts.textContent = (accountsResult.accounts || []).length;
        } else {
            elements.totalAccounts.textContent = '0';
            updateAdminAccountsDisplay([]);
        }

    } catch (error) {
        console.error('Error loading admin settings and accounts:', error);
        // Update with empty data on error
        elements.totalAccounts.textContent = '0';
        updateAdminAccountsDisplay([]);
    }
};
