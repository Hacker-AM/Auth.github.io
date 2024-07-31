//login/app.js
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const nocache = require('nocache');
const flash = require('express-flash');
const db = require('./config/database');
const { router: authRouter, isAuthenticated } = require('./routes/authRoute');

const app = express();

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Use express-flash middleware
app.use(flash());

app.use(express.static('public'));

app.use(nocache());

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render("register");
});

// Include the authentication routes
app.use('/', authRouter);

app.get('/dashboard', isAuthenticated, (req, res) => {
    const user = req.user;
    if (user) {
        res.render('dashboard', { user });
    } else {
        console.error('User not found in the session.');
        res.redirect('/login');
    }
});

// Add this middleware to reset the counter daily
setInterval(() => {
    db.query('UPDATE users SET reset_request_count = 0, reset_token = NULL, reset_token_expires = NULL', (err, results) => {
        if (err) {
            console.error('Error resetting reset_request_count:', err);
        } else {
            console.log('Reset reset_request_count successfully.');
        }
    });
}, 1 * 60 * 60 * 1000); // Reset every 1 hour

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on Port 3000`);
});