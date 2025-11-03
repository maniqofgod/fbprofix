const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Database setup
const dbPath = path.join(__dirname, 'reelsync.db');
const db = new sqlite3.Database(dbPath);

console.log('🔧 Adding test user to database...');

// Add a test user
const username = 'testuser';
const password = 'testpass123';
const displayName = 'Test User';

// Check if user already exists
const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
if (existingUser) {
    console.log('❌ Test user already exists');
    db.close();
    process.exit(0);
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

stmt.run(userId, username, hashedPassword, displayName, 'user', new Date().toISOString());

console.log('✅ Test user added successfully!');
console.log(`   Username: ${username}`);
console.log(`   Password: ${password}`);
console.log(`   Display Name: ${displayName}`);
console.log(`   Role: user`);
console.log(`   User ID: ${userId}`);

db.close();
