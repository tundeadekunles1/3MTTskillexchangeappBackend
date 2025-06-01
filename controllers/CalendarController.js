import SessionSchedule from "../models/SessionSchedule.js";

export const getCalendarEvents = async (req, res) => {
  try {
    const { start, end } = req.query;

    const sessionSchedules = await SessionSchedule.find({
      "allSessions.date": { $gte: new Date(start), $lte: new Date(end) },
    })
      .populate({
        path: "sessionId",
        populate: [
          { path: "teacherId", model: "User", select: "fullName" },
          { path: "learnerId", model: "User", select: "fullName" },
        ],
      })
      .lean();

    const events = sessionSchedules.flatMap((schedule) =>
      schedule.allSessions
        .filter(
          (session) =>
            new Date(session.date) >= new Date(start) &&
            new Date(session.date) <= new Date(end)
        ) //Filter
        .map((session) => ({
          start: session.date,
          end: new Date(session.date.getTime() + 60 * 60 * 1000),
          title: `Learning ${schedule.sessionId.skill} with ${schedule.sessionId.teacherId.fullName}`,
          skill: schedule.sessionId.skill,
          teacherName: schedule.sessionId.teacherId.fullName,
          learnerName: schedule.sessionId.learnerId.fullName,
          sessionId: schedule.sessionId._id,
          backgroundColor: "#4CAF50",
          borderColor: "#4CAF50",
          textColor: "#FFFFFF",
        }))
    );

    res.json(events);
  } catch (error) {
    res.status(500).json({ message: "Failed", error: error.message });
  }
};
