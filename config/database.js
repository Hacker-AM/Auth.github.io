//login/config/database.js
const mysql = require('mysql2');
require('dotenv').config();

// Create a connection connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: '',
    database: process.env.DB_NAME,
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
      throw err;
    }
    console.log('Connected to MySQL');
  });

module.exports = db;