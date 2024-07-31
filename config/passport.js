//login/config/passport.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('../model/user');
const bcrypt = require('bcrypt');

passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
}, (username, password, done) => {
    // Find user by username
    User.findUserByUsername(username, (err, user) => {
        if (err) {
            console.error('Error finding user by username:', err);
            return done(err);
        }
        if (!user) {
            console.log('User not found with username:', username);
            return done(null, false, { message: 'Incorrect username.' });
        }
        // Check if the password is correct
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return done(err);
            }
            if (isMatch) {
                // Check if the user already has an auth token
                if (user.auth_token && user.auth_token_expires > new Date()) {
                    console.log('User already has an active auth token.');
                    // Use the existing token and extend the expiration
                    return done(null, { user, token: user.auth_token });
                } else {
                    // Generate a new authentication token
                    const token = User.generateAuthToken(user);
                    const authTokenExpires = User.generateAuthTokenExpires();
                    // Update user with the new auth token
                    User.updateUserAuthToken(user.username, token, authTokenExpires, (err) => {
                        if (err) {
                            console.error('Error storing authentication token:', err);
                            return done(err);
                        }
                        console.log('User authenticated successfully:', username);
                        return done(null, { user, token });
                    });
                }
            } else {
                console.log('Incorrect password for user:', username);
                return done(null, false, { message: 'Incorrect password.' });
            }
        });
    });
}));

//Serialize user from session storage
passport.serializeUser((user, done) => {
    const userId = user.id || (user.user && user.user.id);
    if (!userId) {
        console.error('User object is missing the "id" property.');
        return done(new Error('User object is missing the "id" property.'), null);
    }
    done(null, userId);
});

// Deserialize user from session storage
passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        if (err) {
            console.error('Error deserializing user:', err);
            return done(err);
        }
        if (!user) {
            console.error('User not found during deserialization.');
            return done(null, false);
        }
        done(null, user);
    });
});

module.exports = passport;