const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Database setup
const dbPath = path.join(__dirname, 'reelsync.db');
const db = new sqlite3.Database(dbPath);

// User Authentication Helper Functions
function registerUser(username, password, displayName, role = 'user') {
    try {
        // Check if user already exists
        const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
        if (existingUser) {
            console.log(`User ${username} already exists. Skipping creation.`);
            return { success: false, error: 'Username already exists' };
        }

        // Check if this is the first user - make them admin
        const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
        if (userCount.count === 0) {
            role = 'admin';
        }

        // Hash password
        const saltRounds = 10;
        const hashedPassword = bcrypt.hashSync(password, saltRounds);

        // Insert new user
        const userId = uuidv4();
        const stmt = db.prepare(`
            INSERT INTO users (id, username, password_hash, display_name, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `);

        stmt.run(userId, username, hashedPassword, displayName || username, role, new Date().toISOString());

        console.log(`✅ Admin user created successfully:`);
        console.log(`   Username: ${username}`);
        console.log(`   Password: ${password}`);
        console.log(`   Role: ${role}`);
        console.log(`   User ID: ${userId}`);

        return { success: true, userId, role };
    } catch (error) {
        console.error('Error registering user:', error);
        return { success: false, error: error.message };
    }
}

// Main execution
console.log('🔄 Adding admin user...');

// Add the admin user with the specified credentials
const result = registerUser('admin', '!*GanTeng188', 'Administrator', 'admin');

if (result.success) {
    console.log('✅ Admin user setup completed successfully!');
} else {
    console.log('❌ Failed to create admin user:', result.error);
}

// Close database connection
db.close((err) => {
    if (err) {
        console.error('Error closing database:', err);
    } else {
        console.log('📊 Database connection closed.');
    }
});
