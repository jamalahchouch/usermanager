const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET = "supersecret";


const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "usermanager",
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

 
app.post("/register", async (req, res) => {
  const { email, password, role, fonction, address, phone, image } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO users (email, password, role, fonction, address, phone, image) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [email, hashedPassword, role || "utilisateur", fonction, address, phone, image]
    );
    res.json({ message: "Utilisateur créé avec succès" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur création utilisateur" });
  }
});


app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(400).json({ error: "Utilisateur introuvable" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Mot de passe invalide" });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      SECRET,
      { expiresIn: "2h" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Erreur serveur login" });
  }
});


app.get("/users", authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT id, email, role, fonction, address, phone, image FROM users");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Erreur récupération utilisateurs" });
  }
});


app.delete("/users/:id", authenticateToken, async (req, res) => {
  try {
    await db.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    res.json({ message: "Utilisateur supprimé" });
  } catch (err) {
    res.status(500).json({ error: "Erreur suppression utilisateur" });
  }
});


app.put("/users/:id", authenticateToken, async (req, res) => {
  const { email, role, fonction, address, phone, image } = req.body;
  try {
    await db.query(
      "UPDATE users SET email=?, role=?, fonction=?, address=?, phone=?, image=? WHERE id=?",
      [email, role, fonction, address, phone, image, req.params.id]
    );
    res.json({ message: "Utilisateur modifié" });
  } catch (err) {
    res.status(500).json({ error: "Erreur modification utilisateur" });
  }
});

app.listen(5000, () => console.log("Backend démarré sur http://localhost:5000"));
