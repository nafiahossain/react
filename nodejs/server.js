const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3019;
const jwtSecret = 'your_jwt_secret'

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'admin',
    password: 'p@stgress',
    port: 5433,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });


// Middleware to authenticate JWT and attach user ID to request
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};


app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const client = await pool.connect();
        const result = await client.query(
            'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
            [username, email, hashedPassword]
        );
        client.release();

        res.status(201).json({ message: 'User registered successfully', user: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// User Login Endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const client = await pool.connect();
        const result = await client.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );
        client.release();

        if (result.rows.length === 0) {
            return res.status(401).send('Invalid credentials');
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send('Invalid credentials');
        }

        const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });

        res.status(200).json({ message: 'User login successful', token });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

// Update User Profile Endpoint
app.put('/update-profile', authenticateToken, async (req, res) => {
    const { email, password } = req.body;
    const userId = req.user.userId;

    try {
        const updates = [];
        const values = [];

        if (email) {
            updates.push(`email = $${updates.length + 1}`);
            values.push(email);
        }

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updates.push(`password = $${updates.length + 1}`);
            values.push(hashedPassword);
        }

        if (updates.length === 0) {
            return res.status(400).send('No updates provided');
        }

        values.push(userId); // User ID for the WHERE clause
        const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING id`;
        const client = await pool.connect();
        const result = await client.query(query, values);
        client.release();

        if (result.rowCount === 0) {
            return res.status(404).send('User not found');
        }

        res.status(200).json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.post('/upload-profile-picture', authenticateToken, upload.single('profilePicture'), async (req, res) => {
    const userId = req.user.userId;
    const file = req.file;

    if (!file) {
        return res.status(400).send('No file uploaded');
    }

    try {
        const profilePicturePath = `/uploads/${file.filename}`;

        const client = await pool.connect();
        try {
            const result = await client.query(
                'UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING id',
                [profilePicturePath, userId]
            );

            if (result.rowCount === 0) {
                return res.status(404).send('User not found');
            }

            res.status(200).json({ message: 'Profile picture uploaded successfully', profilePicturePath });
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('Database error:', err.message);
        res.status(500).send('Server error');
    }
});


// Ensure 'uploads' directory exists
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
