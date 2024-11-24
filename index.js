import express, { json } from "express";
import "dotenv/config";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { authenticateJWT } from "./middleware/authenticateJWT.js";
import { authorizeRole } from "./middleware/authorizeRole.js";

const app = express();
app.use(express.json());
const db = [];
const jwt_secret = process.env.JWT_KEY;
const port = process.env.PORT || 3333;

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
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
    name,
    email,
    password: hashedPassword,
    role: "user",
  };
  db.push(user);

  res.status(200).json({ message: "user is registered" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.find((user) => user.email === email);
  if (!user) {
    return res.status(400).json({ error: "wrong credentials" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ error: "wrong credentials" });
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

  db.splice(userIndex, 1);

  res.status(200).json({ message: "account was deleted" });
});

app.post(
  "/role-update",
  authenticateJWT,
  authorizeRole("admin"),
  (req, res) => {
    const { userId, newRole } = req.body;

    const validRoles = ["admin", "user"];

    if (!userId || !newRole) {
      return res.status(400).json({ message: "credentials are required" });
    }

    const user = db.find((user) => user.id === userId);
    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }

    if (!validRoles.includes(newRole)) {
      return res.status(400).json({ message: "invalid role" });
    }

    if (user.role === newRole) {
      return res.status(400).json({ message: "role is already assigned" });
    }

    user.role = newRole;

    res.status(200).json({ message: "user role updated", user });
  }
);

app.post("/refresh-token", authenticateJWT, async (req, res) => {
  const authTokenHeader = req.headers.authorization;

  if (!authTokenHeader) {
    return res.status(401).json({ error: "token is required" });
  }

  const token = authTokenHeader.split(" ")[1];

  jwt.verify(token, jwt_secret, { ignoreExpiration: true }, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "invalid token" });
    }
    const newToken = jwt.sign({ id: user.id, email: user.email }, jwt_secret, {
      expiresIn: "5h",
    });

    return res
      .status(200)
      .json({ message: "token has been updated", token: newToken });
  });
});

app.put("/update-email", authenticateJWT, async (req, res) => {
  const { email } = req.body;

  const emailExists = db.find((user) => user.email === email);
  if (emailExists) {
    return res.status(400).json({ error: "email in use" });
  }

  if (!email) {
    return res.status(400).json({ message: "email is required" });
  }

  const user = db.find((user) => user.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: "user not found" });
  }

  user.email = email;

  res.status(200).json({ message: "email was updated", user });
});

app.listen(port, () => {
  console.log(`server is running on http://localhost:${port}`);
});
