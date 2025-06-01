import express from "express";
const router = express.Router();

import { sendMessage, getConversation } from "../controllers/MessageController";

// POST /api/messages
router.post("/", sendMessage);

// GET /api/messages/:userId1/:userId2
router.get("/:userId1/:userId2", getConversation);

export default router;
