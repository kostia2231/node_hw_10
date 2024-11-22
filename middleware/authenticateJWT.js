import jwt from "jsonwebtoken";
import "dotenv/config";
const jwt_secret = process.env.JWT_KEY;

export function authenticateJWT(req, res, next) {
  const { auth } = req.headers["authorization"];
  const token = auth && auth.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "token is wrong" });
  }

  jwt.verify(token, jwt_secret, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "token is wrong" });
    }
    req.user = user;
    next();
  });
}
