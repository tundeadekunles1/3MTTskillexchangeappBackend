import express from "express";
import {
  approveMatchRequest,
  getMatchRequestById,
} from "../controllers/MatchRequestController.js";
import { authenticate } from "../middlewares/AuthMiddlewares.js";

const router = express.Router();

router.put("/:id/approve", authenticate, approveMatchRequest);

// router.get(
//   "/by-participant/:userId",
//   authenticate,
//   getApprovedMatchByParticipant
// );
router.get("/:id", getMatchRequestById);

export default router;
