//login/model/user.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/database');

// Model to handle user-related database operations
// Function to find a user by username
function findUserByUsername(username, callback) {
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return callback(err, null); // Updated error handling
        }
        if (results.length === 0) {
            console.log('User not found with username:', username);
            return callback(null, null);
        }
        const user = results[0];
        console.log('Found user:', user.username);
        if (!user) {
            console.log('User not found with username:', username);
            return callback(null, null);
        }
        // Ensure 'user' has a direct 'id' property
        user.id = user.id || (user.user && user.user.id);
        // Ensure the user object has an 'id' property
        if (!user.hasOwnProperty('id')) {
            console.error('User object is missing the "id" property.');
            return callback(new Error('User object is missing the "id" property.'), null);
        }
        callback(null, user);
    });
}

//Function to insert new user into DB
function createUser(username, password, callback) {
    // Hash the password before storing it
    bcrypt.hash(password, 5, (err, hash) => {
        if (err) throw err;
        
        // Store hashed password in the database
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], (err, results) => {
            if (err) throw err;
            callback(results.insertId);
        });
    });
}

//Function to update reset token to DB
function updateUserResetToken(username, resetToken, resetTokenExpires, callback) {
    db.query('UPDATE users SET reset_token = ?, reset_token_expires = ?, reset_request_count = reset_request_count + 1 WHERE username = ?', [resetToken, resetTokenExpires, username], (err, results) => {
        if (err) {
            console.error('Error updating reset token:', err);
            return callback(err);
        }
        callback(null, results);
    });
}

//Function to get reset token from DB
function getUserByResetToken(resetToken) {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()', [resetToken], (err, results) => {
            if (err) {
                console.error('Error querying database for reset token:', err);
                reject(err);
            } else if (results.length === 0) {
                const error = new Error('User not found with reset token:', resetToken);
                console.error(error);
                reject(error);
            } else {
                const user = results[0];
                console.log('User found:', user);
                resolve(user);
            }
        });
    });
}

//Function to Update user new password
function updateUserPassword(username, newPassword, callback) {
        // Update the user's password in the database
        db.query('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE username = ?', [newPassword, username], (updateErr, results) => {
            if (updateErr) {
                console.error('Error updating user password:', updateErr);
                if (callback) {
                    return callback(updateErr);
                }
            }
            if (callback) {
                callback(null, results);
            }
        });
}

// Function to generate JWT token
function generateAuthToken(user) {
    return jwt.sign({ username: user.username }, 'abhishek', { expiresIn: '1h', algorithm: 'HS256' });
}

// Function to generate auth_token_expires time
function generateAuthTokenExpires() {
    const expirationDate = new Date();
    expirationDate.setHours(expirationDate.getHours() + 1);
    return expirationDate;
}

// Function to update user authentication token
function updateUserAuthToken(username, authToken, authTokenExpires, callback) {
    db.query('UPDATE users SET auth_token = ?, auth_token_expires = ? WHERE username = ?', [authToken, authTokenExpires, username], (err, results) => {
        if (err) {
            console.error('Error updating authentication token:', err);
            return callback(err);
        }
        callback(null, results);
    });
}

// Function to find a user by ID
function findById(id, callback) {
    db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return callback(err, null); // Updated error handling
        }

        const user = results[0];
        if (!user) {
            console.log('User not found with ID:', id);
            return callback(null, null);
        }

        // Ensure 'user' has a direct 'id' property
        user.id = user.id || (user.user && user.user.id);

        // Ensure the user object has an 'id' property
        if (!user.hasOwnProperty('id')) {
            console.error('User object is missing the "id" property.');
            return callback(new Error('User object is missing the "id" property.'), null);
        }

        callback(null, user);
    });
}

//Function to delete AuthToken from database
function deleteAuthToken(username, callback) {
    db.query('UPDATE users SET auth_token = NULL, auth_token_expires = NULL  WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error deleting authentication token:', err);
            return callback(err);
        }

        callback(null, results);
    });
}

// Function to update user details
function updateUserDetails(username, userDetails, callback) {
    const { email, firstName, lastName } = userDetails;
    db.query(
        'UPDATE users SET email = ?, first_name = ?, last_name = ? WHERE username = ?',
        [email, firstName, lastName, username],
        (err, results) => {
            if (err) {
                console.error('Error updating user details in the database:', err);
                return callback(err);
            }
            // Assuming that the update was successful
            callback(null, results);
        }
    );
}

module.exports = {
    findUserByUsername,
    createUser,
    updateUserResetToken,
    getUserByResetToken,
    updateUserPassword,
    generateAuthToken,
    updateUserAuthToken,
    findById,
    deleteAuthToken,
    generateAuthTokenExpires,
    updateUserDetails
};