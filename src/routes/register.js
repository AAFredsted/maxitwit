const express = require('express');
const bcrypt = require('bcrypt');
const UserService = require('../services/userService');
const router = express.Router();
const userService = new UserService();

// Helper function for validating email
const validateEmail = (email) => String(email)
  .toLowerCase()
  .match(
    /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
  );

// Extracted validation logic
function validateUserInput({ username, email, password, password2 }) {
  const errors = [];
  if (!username) errors.push('You have to enter a username');
  if (!validateEmail(email)) errors.push('You have to enter a valid email address');
  if (password !== password2) errors.push('The two passwords do not match');
  if (!password) errors.push('You have to enter a password');
  return errors;
}

// Middleware for handling flash messages
router.use((req, res, next) => {
  res.locals.success_messages = req.flash('success');
  res.locals.error_messages = req.flash('error');
  next();
});

// Utility for extracting user credentials from session
function getUserCredentialsFromSession(req) {
  if (req.session.username) {
    return {
      user: {
        id: req.session.username.id,
        username: req.session.username.username,
      },
    };
  }
  return { user: {} };
}

// Registration page route
router.get('/', (req, res) => {
  const g = getUserCredentialsFromSession(req);
  res.render('register', { title: 'Register', g });
});

// Registration logic route
router.post('/', async (req, res) => {
  const errors = validateUserInput(req.body);
  if (errors.length > 0) {
    errors.forEach(error => req.flash('error', error));
    return res.redirect('/register');
  }

  const { username, email, password } = req.body;
  try {
    const emailExists = await userService.getUserIdByEmailIfExists(email);
    const usernameExists = await userService.getUserIdByUsernameIfExists(username);

    if (emailExists || usernameExists) {
      req.flash('error', 'Username or email already exists');
      return res.redirect('/register');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await userService.registerUser(username, email, hashedPassword);
    req.flash('success', 'You were successfully registered and can now log in');
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    req.flash('error', 'An error occurred, please try again later.');
    res.redirect('/register');
  }
});

module.exports = router;
