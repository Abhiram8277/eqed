import express from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const SECRET = "mysecretkey"; // Replace with env variable in production

// --- Example Users with Roles ---
const users = [
  { id: 1, name: "Alice", role: "student" },
  { id: 2, name: "Bob", role: "mentor" },
  { id: 3, name: "Charlie", role: "sponsor" },
  { id: 4, name: "Admin", role: "admin" }
];

// --- Generate JWT for a user ---
app.post("/login", (req, res) => {
  const { id } = req.body;
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// --- Middleware for Role Verification ---
function verifyRole(allowedRoles) {
  return (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "No token provided" });

    const token = authHeader.split(" ")[1];
    jwt.verify(token, SECRET, (err, decoded) => {
      if (err) return res.status(403).json({ error: "Invalid token" });

      if (!allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ error: "Access denied" });
      }

      req.user = decoded;
      next();
    });
  };
}

// --- Protected Routes ---
app.get("/student-dashboard", verifyRole(["student", "admin"]), (req, res) => {
  res.json({ message: `Welcome Student, ${req.user.role}` });
});

app.get("/mentor-dashboard", verifyRole(["mentor", "admin"]), (req, res) => {
  res.json({ message: `Welcome Mentor, ${req.user.role}` });
});

app.get("/sponsor-dashboard", verifyRole(["sponsor", "admin"]), (req, res) => {
  res.json({ message: `Welcome Sponsor, ${req.user.role}` });
});

app.get("/admin-panel", verifyRole(["admin"]), (req, res) => {
  res.json({ message: "Welcome Admin!" });
});

// --- Start Server ---
app.listen(3000, () => {
  console.log("✅ Server running on http://localhost:3000");
});
