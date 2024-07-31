//login/routes/authRoute.js
const express = require('express');
const router = express.Router();
const userModel = require('../model/user');
const passport = require('../config/passport');
const bcrypt =  require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

//Middleware to Check whether user is authorize or not. 
const isAuthenticated = (req, res, next) => {
    const user = req.user;
    if (!user || !user.auth_token) {
        return res.redirect('/login'); // Redirect to login if token is not present
    }
    // Check if the auth_token has expired
    const tokenExpiration = new Date(user.auth_token_expires);
    const currentDateTime = new Date();
    if (tokenExpiration <= currentDateTime) {
        // Token has expired, perform logout
        userModel.deleteAuthToken(user.username, (err) => {
            if (err) {
                console.error('Error deleting authentication token:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            req.logout((logoutErr) => {
                if (logoutErr) {
                    console.error('Error during logout:', logoutErr);
                    return res.status(500).json({ message: 'Error logging out' });
                }
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying session:', err);
                        // Handle the error as needed
                        res.status(500).send('Internal Server Error');
                    } else {
                        // Redirect to the login page or any other desired location
                        res.clearCookie('connect.sid');
                        return res.redirect('/login');
                    }
                });
            });
        });
    } else {
        // Token is still valid, continue with the next middleware
        next();
    }
};

router.get('/dashboard', isAuthenticated, (req, res) => {
    const user = req.user;
    if (user) {
        res.render('dashboard', { user });
    } else {
        console.error('User not found in the session.');
        res.redirect('/login'); // Redirect to login if user is not found
    }
});

// Login Page GET Method
router.get('/login', (req, res) => {
    res.render('login', { message: req.flash('error') });
});

// Login Page POST Method
router.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true
})); 

// Register Page GET Method
router.get('/register', (req, res) => {
    res.render('register');
});

// Register Page POST Method
router.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Check if the username is already taken
    userModel.findUserByUsername(username, (err, foundUser) => {
        if (err) {
            console.error('Error finding user by username:', err);
            return res.status(500).send('Internal Server Error');
        }
        if (foundUser) {
            // Username is already taken
            const errorMessage = 'Username is already taken.';
            return res.render('register', { errorMessage });
        } else {
            // Create a new user
            userModel.createUser(username, password, (userId) => {
                // Registration successful, redirect to login in the auth namespace
                res.render('login');
            });
        }
    });
});

// Logout
router.get('/logout', (req, res) => {
    if (req.user && req.user.username) {
        const username = req.user.username;
        // Call the function to delete the authentication token
        userModel.deleteAuthToken(username, (err) => {
            if (err) {
                console.error('Error deleting authentication token:', err);
                // Handle the error, e.g., send an error response
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            req.logout((logoutErr) => {
                if (logoutErr) {
                    console.error('Error during logout:', logoutErr);
                    return res.status(500).json({ message: 'Error logging out' });
                }
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying session:', err);
                        // Handle the error as needed
                        res.status(500).send('Internal Server Error');
                    } else {
                        // Redirect to the login page or any other desired location
                        res.clearCookie('connect.sid');
                        res.redirect('/login');
                    }
                });
            });
        });
    } else {
        // Handle the case where req.user or req.user.username is undefined
        console.error('User not authenticated.');
        res.redirect('/login'); // Redirect to login or handle as appropriate
    }
});

// Forgot Password Page GET Method
router.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

// Forgot Password Page POST Method
router.post('/forgot-password', (req, res) => {
    const { username } = req.body;

    // Check if the user has exceeded the limit
    userModel.findUserByUsername(username, (err, user) => {
        if (err) {
            console.error('Error finding user by username:', err);
            // Handle the error
            return res.status(500).send('Internal Server Error');
        }

        if (user && user.reset_request_count >= 5) {
            // User has exceeded the limit
            return res.render('limitsendlink');
        }

    // Generate reset token
    const resetToken = jwt.sign({ username }, 'abhishek', { expiresIn: '10m',algorithm: 'HS256' });
    const resetTokenExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Update user with reset token
    userModel.updateUserResetToken(username, resetToken, resetTokenExpires, (err, results) => {
        if (err) {
            console.error('Error updating reset token:', err);
            res.render('error');
        } else {
            // Send reset email
            sendResetEmail(username, resetToken);
            res.render('reset-email-sent');
        }
    });
});
});

// Reset Password Page GET Method
router.get('/reset-password/:token', async (req, res) => {
    const resetToken = req.params.token;

    try {
        const user = await userModel.getUserByResetToken(resetToken);
        console.log('Rendering reset-password page for user:', user);
        res.render('reset-password', { resetToken });
    } catch (err) {
        console.error('Error finding user by reset token:', err);
        res.render('error');
    }
});

// Reset Password Page POST Method
router.post('/reset-password/:token', async (req, res) => {
    const resetToken = req.params.token;
    const { resetpassword } = req.body;

    try {
        // Find user by reset token
        const user = await userModel.getUserByResetToken(resetToken);

        if (!user) {
            console.error('User not found with reset token:', resetToken);
            return res.render('error');
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(resetpassword, 10);

        // Update the user's password
        await userModel.updateUserPassword(user.username, hashedPassword);

        res.render('password-reset-success');
    } catch (error) {
        console.error('Error resetting password:', error);
        res.render('error');
    }
});

// Helper function to send reset email
function sendResetEmail(username, resetToken) {
    // Configure nodemailer
    const transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        auth: {
            user: 'reuben.wintheiser84@ethereal.email',
            pass: 'fQv52sT4QRumEytTSa',
        },
    });

    // Define email content
    const mailOptions = {
        from: 'security@edcite.com',
        to: 'user@email.com',
        subject: 'Password Reset Link',
        text: `To reset your password, click the following link: http:/localhost:3000/reset-password/${resetToken}`,
    };

    // Send email
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.error('Error sending reset email:', err);
        } else {
            console.log('Reset email sent:', info);
        }
    });
}

// Profile Edit Page GET Method
router.get('/editProfile', isAuthenticated, (req, res) => {
    const user = req.user;
    if (user) {
        res.render('editprofile', { user, message: req.flash('editProfileMessage') });
    } else {
        console.error('User not found in the session.');
        res.redirect('/login');
    }
});

// Profile Edit Page POST Method
router.post('/editProfile', isAuthenticated, (req, res) => {
    const authenticatedUser = req.user;
    const { username, email, firstName, lastName, password } = req.body;
    userModel.findUserByUsername(username, (err, foundUser) => {
        if (err) {
            console.error('Error finding user by username:', err);
            req.flash('editProfileMessage', 'Error updating profile. Please try again.');
            return res.redirect('/dashboard');
        }
        if (!foundUser) {
            console.log('User not found with username:', username);
            req.flash('editProfileMessage', 'User not found.');
            return res.redirect('/dashboard');
        }
        bcrypt.compare(password, foundUser.password, (compareErr, isMatch) => {
            if (compareErr || !isMatch) {
                console.log('Incorrect password for user:', username);
                req.flash('editProfileMessage', 'Incorrect password. Profile not updated.');
                return res.redirect('/dashboard');
            }
            userModel.updateUserDetails(username, { email, firstName, lastName }, (updateErr, updatedUser) => {
                if (updateErr) {
                    console.error('Error updating user details:', updateErr);
                    req.flash('editProfileMessage', 'Error updating profile. Please try again.');
                    return res.redirect('/editProfile');
                }
                req.flash('editProfileMessage', 'Profile updated successfully.');
                return res.redirect('/dashboard');
            });
        });
    });
});

//Exporting modules
module.exports = {
    isAuthenticated,
    router
};