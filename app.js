import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import session from 'express-session';
import sanitizeHtml from 'sanitize-html';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet'
import cookieParser from 'cookie-parser';
import csurf from 'csurf';
import zxcvbn from 'zxcvbn';

dotenv.config();
const PORT = 8070;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

//-------------Middleware----------------------

app.use(express.static(path.join(__dirname, 'views')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,   
    sameSite: 'strict', // Prevents CSRF by restricting cookie sharing across sites
    maxAge: 1000 * 60 * 30 // Session expires in 30 minutes (adjust as needed)
  }
}));
app.use('/public', express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  extensions: ['html', 'css', 'js']
}));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],  // Allow content only from the same origin
      scriptSrc: ["'self'", "'unsafe-inline'", "https://trusted.cdn.com"], // Allow inline scripts
      styleSrc: ["'self'", "'unsafe-inline'", "https://trusted.cdn.com"],  // Allow inline styles
      imgSrc: ["'self'", "data:", "https://images.example.com"],  // Allow images
      objectSrc: ["'none'"],  // Block plugins like Flash
      formAction: ["'self'"],  // Allow form submissions from the same origin
      connectSrc: ["'self'", "http://localhost:8070"], // Allow API requests to backend
      upgradeInsecureRequests: [],  // Upgrade HTTP to HTTPS
    },
  },
}));
app.use(cookieParser());
app.use(csurf({ cookie: true }));


const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, //10 mins
  max: 5, // Max 5 attempts
  message: { success: false, message: "Too many login attempts. Try again later." },
  headers: true,
});

const dbPromise = open({
  filename: path.join(__dirname, '/database/CS4417.db'),
  driver: sqlite3.Database
});

function requireAuth(req, res, next) {
  if (!req.session.userId) {
      return res.redirect('/login');
  }
  next();
}

app.get('/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// GET /
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// GET /login
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

// POST /login
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
      return res.json({ success: false, message: 'Username and password are required.' });
  }

  try {
      const db = await dbPromise;
      const user = await db.get(`SELECT userId, password FROM Users WHERE username = ?`, [username]);

      if (!user || !(await bcrypt.compare(password, user.password))) {
          return res.json({ success: false, message: 'Invalid username or password.' });
      }

      req.session.userId = user.userId;

      req.session.save(err => {
          if (err) {
              console.error("Session Save Error:", err);
              return res.json({ success: false, message: "Session error" });
          }
          res.json({ success: true, redirect: '/homepage' });
      });

  } catch (err) {
      console.error(err);
      res.json({ success: false, message: 'Server error. Try again later.' });
  }
});

// GET /register
app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

// POST /register
app.post('/register', async (req, res) => {
  const { first_name, last_name, username, email, password } = req.body;

  if (!first_name || !last_name || !username || !email || !password) {
      return res.json({ success: false, message: 'All fields are required.' });
  }

  // Sanitize input to remove potential XSS attempts
  const sanitizedFirstName = sanitizeHtml(first_name);
  const sanitizedLastName = sanitizeHtml(last_name);
  const sanitizedUsername = sanitizeHtml(username);
  const sanitizedEmail = sanitizeHtml(email);
  const sanitizedPassword = sanitizeHtml(password);

  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  if (!usernameRegex.test(sanitizedUsername)) {
      return res.json({ success: false, message: 'Username must contain only letters, numbers, and underscores.' });
  }

  const passwordRegex = /^(?!.*\s)(?=.*[A-Z])(?=.*\d)(?=.*[!@#+=$%^&*]).{8,}$/;
  if (!passwordRegex.test(sanitizedPassword)) {
      return res.json({ success: false, message: 'Password must be at least 8 characters long, include a number, a special character, and an uppercase letter.' });
  }

  const passwordStrength = zxcvbn(sanitizedPassword);
  if (passwordStrength.score < 3) {  // Score is from 0 (weak) to 4 (strong)
      return res.json({ 
          success: false, 
          message: 'Password is too weak. Try adding more length, numbers, or symbols.' 
      });
  }

  try {
      const db = await dbPromise;
      const existingUser = await db.get(`SELECT userId FROM Users WHERE username = ? OR email = ?`, [sanitizedUsername, sanitizedEmail]);

      if (existingUser) {
          return res.json({ success: false, message: 'Registration failed. Please try again.' });
      }

      const hashedPassword = await bcrypt.hash(sanitizedPassword, 10);
      await db.run(`INSERT INTO Users (first_name, last_name, username, email, password) VALUES (?, ?, ?, ?, ?)`,
          [sanitizedFirstName, sanitizedLastName, sanitizedUsername, sanitizedEmail, hashedPassword]
      );

      res.json({ success: true, message: 'Registration successful!', redirect: '/login' });
  } catch (err) {
      console.error(err);
      res.json({ success: false, message: 'Registration failed. Please try again.' });
  }
});

// GET /homepage
app.get('/homepage', requireAuth, async (req, res) => {
  try {
      res.sendFile(path.join(__dirname, 'views', 'homepage.html'));
  } catch (err) {
      console.error(err);
      res.json({ success: false, message: 'Error loading homepage.' });
  }
});

app.post('/homepage', requireAuth, async (req, res) => {
    const { sport, league, team1, score1, team2, score2 } = req.body;

    // Validate that all fields exist
    if (!sport || !league || !team1 || score1 === undefined || !team2 || score2 === undefined) {
        return res.json({ success: false, message: 'All fields are required.' });
    }

    // Convert scores to numbers
    const numScore1 = Number(score1);
    const numScore2 = Number(score2);

    // Validate that scores are **actual numbers** and non-negative
    if (!Number.isInteger(numScore1) || !Number.isInteger(numScore2) || numScore1 < 0 || numScore2 < 0) {
        return res.json({ success: false, message: 'Scores must be whole, non-negative numbers.' });
    }

    // Trim & sanitize text inputs
    const sanitizedSport = sanitizeHtml(sport.trim());
    const sanitizedLeague = sanitizeHtml(league.trim());
    const sanitizedTeam1 = sanitizeHtml(team1.trim());
    const sanitizedTeam2 = sanitizeHtml(team2.trim());

    // Validate input lengths
    if (
        sanitizedSport.length > 50 || 
        sanitizedLeague.length > 50 || 
        sanitizedTeam1.length > 50 || 
        sanitizedTeam2.length > 50
    ) {
        return res.json({ success: false, message: 'Input values are too long (max 50 characters).' });
    }

    // Enforce allowed character set (letters, numbers, spaces, dashes, and apostrophes)
    const nameRegex = /^[a-zA-Z0-9\s\-']+$/;
    if (
        !nameRegex.test(sanitizedSport) || 
        !nameRegex.test(sanitizedLeague) || 
        !nameRegex.test(sanitizedTeam1) || 
        !nameRegex.test(sanitizedTeam2)
    ) {
        return res.json({ success: false, message: 'Invalid characters in input fields.' });
    }

    try {
        const db = await dbPromise;
        
        await db.run(
            `INSERT INTO scores (sport, league, team1_name, team1_score, team2_name, team2_score) 
            VALUES (?, ?, ?, ?, ?, ?)`,
            [sanitizedSport, sanitizedLeague, sanitizedTeam1, numScore1, sanitizedTeam2, numScore2]
        );

        res.json({ success: true, message: 'Score submitted successfully!' });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: 'Database error. Please try again.' });
    }
});

// POST /logout
app.post('/logout', async (req, res) => {
  try {
    // Check if the session exists (IT SHOULD!)
    if (!req.session.userId) {
      return res.json({ success: true, redirect: '/login' });
    }

    // Destroy the session to clear session data
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying session:', err);
        return res.json({ success: false, message: 'Server error. Try again later.' });
      }

      // Clear the session cookie
      res.clearCookie('connect.sid');

      res.json({ success: true, redirect: '/login' });
    });

  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'Server error. Try again later.' });
  }
});

// GET /scores
app.get('/scores', requireAuth, async (req, res) => {
  try {
      const db = await dbPromise;
      const scores = await db.all("SELECT * FROM Scores ORDER BY score_id DESC");
      res.json(scores);
  } catch (err) {
      console.error("Database error:", err);
      res.status(500).json({ message: "Failed to retrieve scores." });
  }
});

// GET /update
app.get('/update', requireAuth, async (req, res) => {
  try {
      const db = await dbPromise;
      const user = await db.get(`SELECT username FROM Users WHERE userId = ?`, [req.session.userId]);

      if (!user) {
          return res.json({ success: false, message: 'Session expired. Please log in again.', redirect: '/login' });
      }

      return res.json({ success: true, redirect: '/update.html' });

  } catch (err) {
      console.error(err);
      res.json({ success: false, message: 'Error loading page.' });
  }
});

// POST /update
app.post('/update', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body;
  const userId = req.session.userId; // Get user ID 

  if (!current_password || !new_password) {
      return res.json({ success: false, message: 'All fields are required.' });
  }

  const passwordRegex = /^(?!.*\s)(?=.*[A-Z])(?=.*\d)(?=.*[!@#+=$%^&*]).{8,}$/;
  if (!passwordRegex.test(new_password)) {
      return res.json({ 
          success: false, 
          message: 'Password must be at least 8 characters long, include a number, a special character, and an uppercase letter.' 
      });
  }

  const passwordStrength = zxcvbn(sanitizedPassword);
  if (passwordStrength.score < 3) {  // Score is from 0 (weak) to 4 (strong)
      return res.json({ 
          success: false, 
          message: 'Password is too weak. Try adding more length, numbers, or symbols.' 
      });
  }

  try {
      const db = await dbPromise;

      // Get the user's current hashed password
      const user = await db.get(`SELECT password FROM Users WHERE userId = ?`, [userId]);
      if (!user) {
          return res.json({ success: false, message: 'User not found.' });
      }

      // Compare password with stored hash
      const match = await bcrypt.compare(current_password, user.password);
      if (!match) {
          return res.json({ success: false, message: 'Current password is incorrect.' });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(new_password, 10);

      // Update password in the database
      await db.run(`UPDATE Users SET password = ? WHERE userId = ?`, [hashedPassword, userId]);

      res.json({ success: true, message: 'Password updated successfully!', redirect: '/homepage' });

  } catch (err) {
      console.error(err);
      res.json({ success: false, message: 'Error updating password. Please try again.' });
  }
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));