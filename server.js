const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const serverrun = `Server is running ${PORT}`;

app.set('view engine', 'ejs');
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// เชื่อมต่อฐานข้อมูล

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_DATA
});

// เช็คการเชื่อมต่อ

db.connect((err) => {
    if (err) {
        console.error('Error connection to database');
    } else {
        console.log('Connected to database');
    }
});

// หน้าแรก

app.get('/', (req, res) => {
    res.render('index', { session: req.session });
});

// หน้าเข้าสู่ระบบ

app.get('/login', (req, res) => {
    res.render('login', {  session: req.session });
});

// หน้าสมัคสมาขิก

app.get('/register', (req, res) => {
    res.render('register', { session: req.session });
});

// หน้าแอดมิน

app.get('/admin', (req, res) => {
    if (req.session.loggedin && req.session.role === 'admin') {
        const sqlUsername = `SELECT username, role FROM users`;
        db.query(sqlUsername, (err, results) => {
            if (err) throw err;
            res.render('admin', { session: req.session, users: results });
        });
    } else {
        res.redirect('/');
    }
});

// หน้าโปรไฟล์

app.get('/profile', (req, res) => {
    if (req.session.loggedin) {
        res.render('profile', { session: req.session });
    } else {
        res.redirect('/login');
    }
});

// สมัคสมาขิก

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const sqlRegister = `INSERT INTO users (username, password) VALUES (?, ?)`;
    bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) throw err;
      db.query(sqlRegister, [username, hash], (err, result) => {
        if (err) throw err;
        res.redirect('/login')
      });
    });
});

// เข้าสู่ระบบ

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sqlLogin = `SELECT * FROM users WHERE username = ?`;
    db.query(sqlLogin, [username], (err, results) => {
      if (err) throw err;
      if (results.length > 0) {
        bcrypt.compare(password, results[0].password, (err, result) => {
          if (err) throw err;
          if (result) {
            req.session.loggedin = true;
            req.session.username = username;
            req.session.role = results[0].role;
            res.redirect('/')
          } else {
            res.send('Incorrect username and/or password');
          }
        });
      } else {
        res.send('User does not exist');
      }
    });
});

// ออกสู่ระบบ

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
      if (err) throw err;
      res.redirect('/');
    });
});

// เปลี่ยนรหัส

app.post('/change-password', (req, res) => {
    const { username, newPassword, confirmPassword } = req.body;
    if (req.session.loggedin) {
        if (newPassword === confirmPassword) {
            const sqlIdPasswordUser = `SELECT id, password FROM users WHERE username = ?`;
            db.query(sqlIdPasswordUser, [username], (err, results) => {
                if (err) throw err;
                if (results.length > 0) {
                    const userId = results[0].id;
                    const hashedPassword = results[0].password;
                    bcrypt.compare(newPassword, hashedPassword, (err, result) => {
                        if (err) throw err;
                        if (!result) {
                            bcrypt.hash(newPassword, saltRounds, (err, hash) => {
                                if (err) throw err;
                                const sqlUpdateSetPassword = `UPDATE users SET password = ? WHERE id = ?`;
                                db.query(sqlUpdateSetPassword, [hash, userId], (err, result) => {
                                    if (err) throw err;
                                    res.send('Password updated successfully');
                                });
                            });
                        } else {
                            res.send('New password must be different from the current one');
                        }
                    });
                } else {
                    res.send('User not found');
                }
            });
        } else {
            res.send('New password and confirm password do not match');
        }
    } else {
        res.redirect('/login');
    }
});

// เพิ่มผู้ใช้

app.post('/admin/add-user', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sqlAddUser = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.query(sqlAddUser, [username, hashedPassword], (err, result) => {
            if (err) {
                console.error("Error adding user:", err);
                return res.status(500).send("An error occurred while adding user");
            }
            console.log("User add successfully");
            res.redirect('/admin');
        });
    } catch (error) {
        console.error("Error hashing password:", error);
        res.status(500).send("An error occurred while hashing password");
    }
});

app.listen(PORT, () => {
    console.log(serverrun);
});