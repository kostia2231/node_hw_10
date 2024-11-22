import express from "express";
import "dotenv/config";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { authenticateJWT } from "./middleware/authenticateJWT.js";

const app = express();
const db = [];
const jwt_secret = process.env.JWT_KEY;
const port = process.env.PORT || 3333;

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "all fields are required" });
  }

  const isExists = db.find((user) => user.email === email);
  if (isExists) {
    return res.status(400).json({ error: "this email is taken" });
  }

  const rounds = 10;
  const hashedPassword = await bcrypt.hash(password, rounds);

  const user = {
    id: db.length + 1,
    username,
    email,
    password: hashedPassword,
  };
  db.push(user);

  res.status(200).json({ message: "user is registered" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.find((user) => user.email === email);
  if (!user) {
    res.status(400).json({ error: "wrong credentials" });
  }

  const isPasswordValid = await bcrypt.compare(password, hashedPassword);
  if (!isPasswordValid) {
    res.status(400).json({ error: "wrong credentials" });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, jwt_secret, {
    expiresIn: "5h",
  });

  res.status(200).json({ message: "log in was successful", token });
});

app.post("/delete-account", authenticateJWT, (req, res) => {
  const userId = req.user.id;
  const userIndex = db.findIndex((user) => user.id === userId);
  if (userIndex === -1) {
    return res.status(404).json({ message: "user not found" });
  }

  db.slice(userIndex, 1);

  res.status(200).json({ message: "account was deleted" });
});

app.put("/update-email", authenticateJWT, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "email is required" });
  }

  const user = db.find((user) => user.id === req.user.id);
  if (!user) {
    res.status(404).json({ error: "user not found" });
  }

  user.email = email;

  res.status(200).json({ message: "email was updated", user });
});

app.listen(port, () => {
  console.log(`server is running on http://localhost:${port}`);
});
