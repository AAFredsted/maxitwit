const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../../db/database');
const router = express.Router();

// Helper function to get user credentials from session
function getUserCredentialsFromSession(req) {
    if (req.session.username) {
        return { user: { id: req.session.username.id, username: req.session.username.username } };
    }
    return { user: {} };
}

// Render the login page with user credentials
router.get('/', (req, res) => {
    const userCredentials = getUserCredentialsFromSession(req);
    res.render('login', { title: 'Login', g: userCredentials });
});

// Login handler
router.post('/', async (req, res) => {
    const { username, password } = req.body;

    // Simple input validation
    if (!username || !password) {
        req.flash('error', 'Please enter both username and password');
        return res.redirect('/login');
    }

    try {
        // Check user in the database
        const sql = 'SELECT * FROM user WHERE username = ?';
        const user = await db.getDb().get(sql, [username]);

        if (!user) {
            req.flash('error', 'Invalid username or password');
            return res.redirect('/login');
        }

        // Compare password with hashed password in the database
        const isPasswordValid = await bcrypt.compare(password, user.pw_hash);

        if (isPasswordValid) {
            req.session.username = { id: user.user_id, username: user.username };
            req.flash('success', 'You were logged in successfully');
            return res.redirect('/');
        } else {
            req.flash('error', 'Invalid username or password');
            return res.redirect('/login');
        }
    } catch (error) {
        console.error(error.message);
        req.flash('error', 'An error occurred while attempting to log in');
        return res.redirect('/login');
    }
});

module.exports = router;
