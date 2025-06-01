import express from "express";
import {
  getMySessions,
  approveSession,
  completeSession,
  proposeSessionCount,
  getLearningSessions,
  getTeachingSessions,
  createSessionFromMatchRequest,
  getSessionById,
  updateSessionStatus,
  getSessionsByUserId,
} from "../controllers/SessionController.js";
import { authenticate } from "../middlewares/AuthMiddlewares.js";

const router = express.Router();

router.get("/my-sessions", authenticate, getMySessions);
router.post("/approve/:id", authenticate, approveSession);
router.post("/complete/:id", authenticate, completeSession);
router.post("/propose-count", authenticate, proposeSessionCount);
router.get("/learning", authenticate, getLearningSessions);
router.get("/teaching", authenticate, getTeachingSessions);
router.post("/:matchRequestId", createSessionFromMatchRequest);
router.get("/:id", authenticate, getSessionById);
router.patch("/:id", authenticate, updateSessionStatus);
router.get("/", authenticate, getSessionsByUserId);

export default router;
