import express from "express";
import { authenticate } from "../middlewares/AuthMiddlewares.js";
import {
  searchTeachersBySkill,
  sendMatchRequest,
  getPendingRequests,
  respondToMatchRequest,
  getTeacherRequests,
  getMyRequests,
  getTeachersByIds,
  cancelMatchRequest,
  declineMatchRequest,
  acceptRequest,
} from "../controllers/MatchController.js";

const router = express.Router();

// Search for teachers by skill
router.get("/search", authenticate, searchTeachersBySkill);

// Learner sends match request to teacher
router.post("/request/:teacherId", authenticate, sendMatchRequest);

// Teacher fetches pending match requests
router.get("/pending", authenticate, getPendingRequests);

// Teacher accepts or declines a request
router.post("/respond/:requestId", authenticate, respondToMatchRequest);
router.get("/teacher-requests", authenticate, getTeacherRequests);

router.post("/get-teachers", authenticate, getTeachersByIds);

router.get("/my-requests", authenticate, getMyRequests);
router.post("/request", authenticate, sendMatchRequest);
router.delete("/match/cancel/:requestId", authenticate, cancelMatchRequest);
router.put("/accept-request/:id", authenticate, acceptRequest);

// New Decline Route
router.delete("/decline-request/:requestId", authenticate, declineMatchRequest);

export default router;
