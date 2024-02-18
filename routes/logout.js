var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
var session = require('express-session');
const db = require('../db/database');

router.use(session({
    secret: 'devving-and-opssing',
    resave: false,
    saveUninitialized: true
}));

router.use(function (req, res, next) {
    res.locals.success_messages = req.flash('success');
    res.locals.error_messages = req.flash('error');
    next();
})

const requireAuth = (req, res, next) => {
    if (req.session.username) {
        next();
    } else {
        res.redirect('/public');
    }
}


router.get('/', requireAuth, function (req, res) {
    req.session.username = null;
    req.flash('success', 'You were logged out');
    res.redirect('/public');
});

module.exports = router;
