import Session from "../models/Session.js";
import MatchRequest from "../models/MatchRequest.js";

export const getMySessions = async (req, res) => {
  try {
    const userId = req.user.id;

    const sessions = await Session.find({
      $or: [{ teacher: userId }, { learner: userId }],
    })
      .populate("teacher", "fullName")
      .populate("learner", "fullName")
      .populate("skill", "name")
      .populate("matchRequestId");

    res.status(200).json({ sessions });
  } catch (error) {
    console.error("Error fetching sessions:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const approveSession = async (req, res) => {
  try {
    const session = await Session.findById(req.params.id);

    if (!session) return res.status(404).json({ message: "Session not found" });
    if (session.teacherId.toString() !== req.user.id)
      return res
        .status(403)
        .json({ message: "Only the teacher can approve this session" });

    session.status = "approved";
    await session.save();

    res.status(200).json({ message: "Session approved", session });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error approving session", error: err.message });
  }
};

export const completeSession = async (req, res) => {
  try {
    const session = await Session.findById(req.params.id);

    if (!session) return res.status(404).json({ message: "Session not found" });

    if (
      session.teacherId.toString() !== req.user.id &&
      session.learnerId.toString() !== req.user.id
    )
      return res.status(403).json({ message: "Unauthorized" });

    session.status = "completed";
    await session.save();

    res.status(200).json({ message: "Session marked as completed", session });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Error completing session", error: err.message });
  }
};

export const proposeSessionCount = async (req, res) => {
  const { teacherId, skill, totalSessions } = req.body;

  try {
    const proposal = {
      learnerId: req.user.id,
      teacherId,
      skill,
      totalSessions,
      agreed: false,
    };

    res.status(200).json({ message: "Session count proposal sent", proposal });
  } catch (err) {
    res
      .status(500)
      .json({ message: "Failed to propose session count", error: err.message });
  }
};

//  getTeachingSessions
export const getTeachingSessions = async (req, res) => {
  try {
    const userId = req.user.id;

    const sessions = await Session.find({ teacherId: userId }) // Directly find sessions where teacherId matches
      .populate({
        path: "learnerId",
        select: "fullName email",
      })
      .populate({
        path: "teacherId",
        select: "fullName email",
      });

    res.status(200).json(sessions);
  } catch (err) {
    console.error("Error fetching teaching sessions:", err.message);
    res
      .status(500)
      .json({ message: "Server error fetching teaching sessions" });
  }
};

//  getLearningSessions
export const getLearningSessions = async (req, res) => {
  try {
    const userId = req.user.id;

    const sessions = await Session.find({ learnerId: userId }) // Directly find sessions where learnerId matches
      .populate({
        path: "teacherId",
        select: "fullName email",
      })
      .populate({
        path: "learnerId",
        select: "fullName email",
      });

    res.status(200).json(sessions);
  } catch (err) {
    console.error("Error fetching learning sessions:", err.message);
    res
      .status(500)
      .json({ message: "Server error fetching learning sessions" });
  }
};

export const createSessionFromMatchRequest = async (req, res) => {
  try {
    const { matchRequestId } = req.params;

    const matchRequest = await MatchRequest.findById(matchRequestId)
      .populate("teacherId", "fullName email")
      .populate("learnerId", "fullName email");
    console.log(matchRequest);

    if (!matchRequest) {
      return res.status(404).json({ message: "Match request not found" });
    }

    if (!matchRequest.teacherId || !matchRequest.learnerId) {
      return res.status(400).json({
        message: "Match request missing teacher or learner",
      });
    }

    const newSession = new Session({
      teacherId: matchRequest.teacherId._id,
      learnerId: matchRequest.learnerId._id,
      matchRequestId: matchRequest._id,
      skill: matchRequest.skill,
      status: "pending",
    });

    await newSession.save();

    return res.status(201).json(newSession);
  } catch (error) {
    console.error("Session creation error:", error);
    return res.status(500).json({
      message: "Failed to create session",
      error: error.message,
    });
  }
};

export const getSessionById = async (req, res) => {
  try {
    const session = await Session.findById(req.params.id).lean();

    if (!session) {
      return res.status(404).json({ message: "Session not found" });
    }

    // Populate teacher and learner from MatchRequest → User
    const match = await MatchRequest.findOne({
      teacher: session.teacherId,
      learner: session.learnerId,
      skill: session.skill,
    })
      .populate("teacher", "fullName email")
      .populate("learner", "fullName email")
      .populate("matchRequestId");

    res.json({
      ...session,
      teacher: match?.teacher || null,
      learner: match?.learner || null,
    });
  } catch (error) {
    console.error("Error fetching session:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const updateSessionStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const session = await Session.findByIdAndUpdate(
      id,
      { status },
      { new: true, runValidators: true }
    );

    if (!session) {
      return res.status(404).json({ message: "Session not found" });
    }

    res.json({ message: "Session status updated successfully", session });
  } catch (error) {
    console.error("Error updating session status:", error);
    res.status(500).json({
      message: "Failed to update session status",
      error: error.message,
    });
  }
};

//get all session
export const getSessionsByUserId = async (req, res) => {
  const userId = req.user.id;

  try {
    const sessions = await Session.find({
      $or: [{ teacherId: userId }, { learnerId: userId }],
    });
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch sessions", error });
  }
};
