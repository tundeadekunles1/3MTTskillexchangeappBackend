import SessionSchedule from "../models/SessionSchedule.js";
import Session from "../models/Session.js";
import { createDailyRoom } from "../controllers/VideoController.js";

export const scheduleSession = async (req, res) => {
  try {
    const {
      sessionId,
      totalWeeks,
      sessionsPerWeek,
      startDate,
      timeSlot,
      daysOfWeek = [1, 3],
      initialNotes,
      learningObjectives,
    } = req.body;

    if (!sessionId || !startDate || !timeSlot) {
      console.error("Validation failed - body:", req.body);
      return res.status(400).json({
        message:
          "Missing required fields: sessionId, startDate, startTime, endTime",
      });
    }

    if (!Array.isArray(daysOfWeek) || daysOfWeek.length === 0) {
      return res
        .status(400)
        .json({ message: "Please select at least one day for sessions" });
    }

    if (sessionsPerWeek < 1 || sessionsPerWeek > 7) {
      return res
        .status(400)
        .json({ message: "Sessions per week must be between 1 and 7" });
    }

    if (daysOfWeek.length < sessionsPerWeek) {
      return res.status(400).json({
        message:
          "Number of selected days cannot be less than sessions per week",
      });
    }

    const sessionToSchedule = await Session.findById(sessionId);
    if (!sessionToSchedule) {
      return res.status(404).json({ message: "Session not found" });
    }
    if (sessionToSchedule.status !== "pending") {
      return res
        .status(400)
        .json({ message: "Session is not in pending status" });
    }

    // Compute duration in minutes from timeSlot
    const startHour = parseInt(timeSlot.startTime.split(":")[0], 10);
    const startMin = parseInt(timeSlot.startTime.split(":")[1], 10);
    const endHour = parseInt(timeSlot.endTime.split(":")[0], 10);
    const endMin = parseInt(timeSlot.endTime.split(":")[1], 10);
    const durationMinutes = endHour * 60 + endMin - (startHour * 60 + startMin);

    const childSessions = [];
    const start = new Date(startDate);
    const selectedDaysSet = new Set(daysOfWeek);

    for (let week = 0; week < totalWeeks; week++) {
      let sessionsThisWeek = 0;
      const currentWeekStart = new Date(start);
      currentWeekStart.setDate(start.getDate() + week * 7);

      for (
        let dayOffset = 0;
        dayOffset < 7 && sessionsThisWeek < sessionsPerWeek;
        dayOffset++
      ) {
        const currentDate = new Date(currentWeekStart);
        currentDate.setDate(currentWeekStart.getDate() + dayOffset);
        const dayOfWeek = currentDate.getDay();

        if (selectedDaysSet.has(dayOfWeek)) {
          const sessionDate = new Date(currentDate);

          //  Create Daily video room
          const roomUrl = await createDailyRoom(sessionDate, durationMinutes);

          childSessions.push({
            date: sessionDate,
            originalDate: new Date(sessionDate),
            timeSlot,
            status: "scheduled",
            notes: initialNotes || "",
            roomUrl, //  Add generated video room
            materialsCovered: learningObjectives
              ? learningObjectives.map((obj) => ({ topic: obj }))
              : [],
          });

          sessionsThisWeek++;
        }
      }
    }

    const newSessionSchedule = new SessionSchedule({
      sessionId: sessionToSchedule._id,
      status: "scheduled",
      startDate,
      totalWeeks,
      sessionsPerWeek,
      preferredDays: daysOfWeek,
      timeSlot,
      allSessions: childSessions,
      notes: initialNotes || "",
      learningObjectives: learningObjectives
        ? learningObjectives.map((obj) => ({ topic: obj }))
        : [],
    });

    await newSessionSchedule.save();

    sessionToSchedule.status = "scheduled";
    await sessionToSchedule.save();

    res.status(201).json({
      success: true,
      data: { session: sessionToSchedule, schedule: newSessionSchedule },
    });
  } catch (err) {
    console.error("Full scheduling error:", {
      message: err.message,
      stack: err.stack,
      error: err,
    });
  }
};

// Update specific class session
export const updateClassSession = async (req, res) => {
  try {
    const { scheduleId, sessionId } = req.params;
    const { status, notes, materials, attendance, newDate, reason } = req.body;

    const schedule = await SessionSchedule.findById(scheduleId);
    if (!schedule)
      return res.status(404).json({ message: "Schedule not found" });

    const session = schedule.allSessions.id(sessionId);
    if (!session) return res.status(404).json({ message: "Session not found" });

    // Validate status transition
    const validTransitions = {
      scheduled: ["completed", "cancelled", "rescheduled"],
      cancelled: ["rescheduled"],
      rescheduled: ["completed", "cancelled"],
    };

    if (
      status &&
      validTransitions[session.status] &&
      !validTransitions[session.status].includes(status)
    ) {
      return res.status(400).json({
        message: `Invalid status transition from ${session.status} to ${status}`,
      });
    }

    // Apply updates
    if (status) session.status = status;
    if (notes) session.notes = notes;
    if (materials) session.materialsCovered = materials;
    if (attendance)
      session.attendance = { ...session.attendance, ...attendance };

    // Handle rescheduling
    if (status === "rescheduled" && newDate) {
      schedule.rescheduleHistory.push({
        originalDate: session.date,
        newDate,
        reason: reason || "",
      });
      session.date = newDate;
    }

    // Handle cancellation
    if (status === "cancelled") {
      schedule.cancellationHistory.push({
        date: new Date(),
        reason: reason || "",
        rescheduledTo: status === "rescheduled" ? newDate : null,
      });
    }

    await schedule.save();

    res.json(schedule);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// Get schedule progress
export const getScheduleProgress = async (req, res) => {
  try {
    const schedule = await SessionSchedule.findById(
      req.params.scheduleId
    ).select("progress allSessions.status");

    if (!schedule)
      return res.status(404).json({ message: "Schedule not found" });

    res.json({
      completionPercentage: schedule.progress.completionPercentage,
      totalSessions: schedule.allSessions.length,
      completedSessions: schedule.allSessions.filter(
        (s) => s.status === "completed"
      ).length,
      lastUpdated: schedule.progress.lastUpdated,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

export const getSchedulesForUser = async (req, res) => {
  const userId = req.user.id;

  try {
    // Find all sessions where the user is either the teacher or learner
    const sessions = await Session.find({
      $or: [{ teacherId: userId }, { learnerId: userId }],
    });

    const sessionIds = sessions.map((s) => s._id.toString());

    // Find schedules for those sessions
    const schedules = await SessionSchedule.find({
      sessionId: { $in: sessionIds },
    });

    res.json(schedules);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch schedules", error });
  }
};
