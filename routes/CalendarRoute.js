import express from "express";
const router = express.Router();
import { getCalendarEvents } from "../controllers/CalendarController.js";
import { authenticate } from "../middlewares/AuthMiddlewares.js";

//  the route to get calendar events
router.get("/calendar-events", authenticate, getCalendarEvents);

export default router;
