import express from "express";
import {
  scheduleSession,
  updateClassSession,
  getScheduleProgress,
  getSchedulesForUser,
} from "../controllers/sessionScheduleController.js";
import validateObjectId from "../middlewares/validateObjectId.js";
import { authenticate } from "../middlewares/AuthMiddlewares.js";

const router = express.Router();

// POST /api/session-schedules - Create new schedule
router.post("/", authenticate, scheduleSession);

router.put("/schedule/:sessionId", authenticate, scheduleSession);

// PATCH /api/session-schedules/:scheduleId/sessions/:sessionId - Update specific session
router.patch(
  "/:scheduleId/sessions/:sessionId",
  validateObjectId("scheduleId"),
  validateObjectId("sessionId"),
  updateClassSession
);

// GET /api/session-schedules/:scheduleId/progress - Get progress
router.get(
  "/:scheduleId/progress",
  validateObjectId("scheduleId"),
  getScheduleProgress
);

// Secured route to get schedules for the logged-in user
router.get("/", authenticate, getSchedulesForUser);

export default router;
