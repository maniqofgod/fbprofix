const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// Database setup
const dbPath = path.join(__dirname, 'reelsync.db');
const db = new sqlite3.Database(dbPath);

console.log('🔍 Checking existing users...');

// Get all users
db.all('SELECT id, username, display_name, role, last_login, created_at FROM users ORDER BY created_at DESC', (err, users) => {
    if (err) {
        console.error('Error getting users:', err);
        db.close();
        return;
    }

    console.log(`📊 Found ${users.length} users:`);
    users.forEach((user, index) => {
        console.log(`${index + 1}. Username: ${user.username}`);
        console.log(`   Display Name: ${user.display_name}`);
        console.log(`   Role: ${user.role}`);
        console.log(`   User ID: ${user.id}`);
        console.log(`   Created: ${user.created_at}`);
        console.log(`   Last Login: ${user.last_login || 'Never'}`);
        console.log('---');
    });

    // Check if admin user exists and verify password
    const adminUser = users.find(u => u.username === 'admin');
    if (adminUser) {
        console.log('🔐 Checking admin user password...');

        // Get the hashed password
        db.get('SELECT password_hash FROM users WHERE username = ?', ['admin'], (err, row) => {
            if (err) {
                console.error('Error getting password hash:', err);
            } else if (row) {
                const isValidPassword = bcrypt.compareSync('!*GanTeng188', row.password_hash);
                console.log(`✅ Admin password verification: ${isValidPassword ? 'CORRECT' : 'INCORRECT'}`);
                if (!isValidPassword) {
                    console.log('🔄 Updating admin password...');
                    const saltRounds = 10;
                    const hashedPassword = bcrypt.hashSync('!*GanTeng188', saltRounds);

                    db.run('UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?',
                        [hashedPassword, new Date().toISOString(), 'admin'], function(err) {
                        if (err) {
                            console.error('Error updating password:', err);
                        } else {
                            console.log('✅ Admin password updated successfully!');
                        }
                        db.close();
                    });
                } else {
                    console.log('✅ Admin user is properly configured.');
                    db.close();
                }
            } else {
                console.log('❌ Admin user not found in password check.');
                db.close();
            }
        });
    } else {
        console.log('❌ Admin user not found. Creating...');

        // Create admin user
        const { v4: uuidv4 } = require('uuid');
        const saltRounds = 10;
        const hashedPassword = bcrypt.hashSync('!*GanTeng188', saltRounds);
        const userId = uuidv4();

        db.run(`INSERT INTO users (id, username, password_hash, display_name, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)`,
            [userId, 'admin', hashedPassword, 'Administrator', 'admin', new Date().toISOString()],
            function(err) {
            if (err) {
                console.error('Error creating admin user:', err);
            } else {
                console.log('✅ Admin user created successfully!');
                console.log(`   Username: admin`);
                console.log(`   Password: !*GanTeng188`);
                console.log(`   User ID: ${userId}`);
            }
            db.close();
        });
    }
});
