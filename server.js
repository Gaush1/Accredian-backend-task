import express from "express";
import mysql from "mysql";
import cors from "cors";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";

// Constants
const salt = 10;
const PORT = 8000;

// Create Express app
const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(cookieParser());

// Database connection
const db = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "",
  database: "authDatabase",
});


// Register API
app.post("/register", (req, res) => {
  const sqlCheckEmail = "SELECT COUNT(*) AS count FROM users WHERE email = ?";
  const sql =
    "INSERT INTO users (`name`,`email`,`phoneNumber`,`password`) VALUES (?)";
  db.query(sqlCheckEmail, [req.body.email], (err, emailResult) => {
    if (err) {
      return res.json({ Error: "Error checking email existence in server" });
    }

    const emailCount = emailResult[0].count;
    if (emailCount > 0) {
      return res.json({ Error: "Email is already occupied" });
    }

    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
      if (err) return res.json({ Error: "Error for hashing Password" });

      const values = [
        req.body.name,
        req.body.email,
        req.body.phoneNumber,
        hash,
      ];
      db.query(sql, [values], (err, result) => {
        if (err) return res.json({ Error: "Inserting data Error in server" });
        return res.json({ Status: "Success" });
      });
    });
  });
});

//Login Api
app.post("/login", (req, res) => {
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Login Error in server" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err) return res.json({ Error: "Password compare error" });
          if (response) {
            return res.json({ Status: "Success" });
          } else {
            return res.json({ Error: "Password not matched!" });
          }
        }
      );
    } else {
      return res.json({ Error: "No email exist!" });
    }
  });
});

app.listen(PORT, console.log(`Listening on port http://localhost:${PORT}`));
