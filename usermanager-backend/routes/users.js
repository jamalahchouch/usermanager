const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../db");
const router = express.Router();

// Middleware auth
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token manquant" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalide" });
    req.user = user;
    next();
  });
}

// POST /register
router.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Champs requis" });

  const hashed = await bcrypt.hash(password, 10);
  db.query("INSERT INTO users (email, password, role) VALUES (?, ?, 'user')", [email, hashed], (err, result) => {
    if (err) return res.status(400).json({ error: "Email déjà utilisé" });
    res.status(201).json({ message: "Utilisateur créé", id: result.insertId });
  });
});

// POST /login
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ error: "Identifiants invalides" });

    const user = results[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Identifiants invalides" });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  });
});

// GET /users (admin)
router.get("/users", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Accès interdit" });

  db.query("SELECT id, email, role FROM users", (err, results) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json(results);
  });
});

// DELETE /users/:id (admin)
router.delete("/users/:id", authenticateToken, (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Accès interdit" });

  db.query("DELETE FROM users WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: "Erreur serveur" });
    res.json({ message: "Utilisateur supprimé" });
  });
});

module.exports = router;
