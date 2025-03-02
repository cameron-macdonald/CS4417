import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bodyParser from 'body-parser';

const PORT = 8070;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(express.static(path.join(__dirname, 'views'))); // Serve static files
app.use(bodyParser.urlencoded({ extended: true })); // Parse form data

// SQLite setup
const dbPromise = open({
  filename: path.join(__dirname, 'CS4417.db'),
  driver: sqlite3.Database
});

//____________________________________________________________
//----------------------------PATHS---------------------------
//____________________________________________________________

// GET login page (default)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

//--------REGISTER-----------
// GET register page
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});
//POST register page
app.post('/register', async (req, res) => {
  const { first_name, last_name, username, email, password } = req.body;
  console.log("enterd");
  if (!first_name || !last_name || !username || !email || !password) {
    return res.status(400).send('All fields are required.');
  }

  try {
    const db = await dbPromise;
    await db.run(
      `INSERT INTO Users (first_name, last_name, username, email, password) VALUES (?, ?, ?, ?, ?)`,
      [first_name, last_name, username, email, password]
    );
    res.send('Registration successful!');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering user. Username or email may already exist.');
  }
});

// Start the server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
