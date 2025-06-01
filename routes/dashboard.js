
import express from "express";
import authMiddleware from "../middleware/auth.js";

const router = express.Router();

router.get("/", authMiddleware, (req, res) => {
  res.json({ message: `Welcome to your dashboard, ${req.user.name}` });
});

export default router;
