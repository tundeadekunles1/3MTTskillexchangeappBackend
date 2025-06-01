import User from "../models/Users.js";
import MatchRequest from "../models/MatchRequest.js";

// Search teachers by skill
export const searchTeachersBySkill = async (req, res) => {
  const { skill } = req.query;

  try {
    const teachers = await User.find({
      skillsOffered: { $regex: new RegExp(skill, "i") },
    }).select("-password");

    res.json(teachers);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error searching teachers", error: error.message });
  }
};

// Send a match request (learner -> teacher)
export const sendMatchRequest = async (req, res) => {
  const learnerId = req.user._id;
  const { teacherId, skill } = req.body;

  try {
    if (!teacherId || !skill) {
      return res.status(400).json({ message: "Missing teacherId or skill" });
    }

    const existingRequest = await MatchRequest.findOne({
      learnerId: learnerId,
      teacherId: teacherId,
      status: "pending",
    });

    if (existingRequest) {
      return res
        .status(400)
        .json({ message: "Request already sent and pending" });
    }

    const newRequest = new MatchRequest({
      learnerId: learnerId,
      teacherId: teacherId,
      skill: skill,
      status: "pending",
    });

    await newRequest.save();

    res.json({ message: "Match request sent, awaiting approval." });
  } catch (error) {
    console.error("Error sending match request:", error);
    res
      .status(500)
      .json({ message: "Error sending match request", error: error.message });
  }
};

// Get pending match requests for teacher
export const getPendingRequests = async (req, res) => {
  const teacherId = req.user._id;

  try {
    const requests = await MatchRequest.find({
      teacher: teacherId,
      status: "pending",
    }).populate("learner", "fullName email");

    res.json(requests);
  } catch (error) {
    res.status(500).json({
      message: "Error fetching pending requests",
      error: error.message,
    });
  }
};

// Teacher responds to a match request (accept/reject)
export const respondToMatchRequest = async (req, res) => {
  const { requestId } = req.params;
  const { action } = req.body; // 'accept' or 'reject'

  try {
    const request = await MatchRequest.findById(requestId);

    if (!request) {
      return res.status(404).json({ message: "Match request not found" });
    }

    if (action === "accept") {
      request.status = "accepted";
    } else if (action === "reject") {
      request.status = "rejected";
    } else {
      return res.status(400).json({ message: "Invalid action" });
    }

    await request.save();

    res.json({ message: `Request ${action}ed successfully.` });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error responding to request", error: error.message });
  }
};

export const getTeacherRequests = async (req, res) => {
  try {
    // Fetch all match requests where the teacher is the logged-in user
    const teacherRequests = await MatchRequest.find({
      teacherId: req.user._id,
    });

    res.status(200).json(teacherRequests);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch teacher requests" });
  }
};

// Fetch match requests made by the current user (learner)
export const getMyRequests = async (req, res) => {
  try {
    const userId = req.user.id;

    const requests = await MatchRequest.find({ learnerId: userId });

    res.status(200).json({ requests });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch your match requests." });
  }
};

export const getTeachersByIds = async (req, res) => {
  try {
    const { teacherIds } = req.body;

    if (!teacherIds || !Array.isArray(teacherIds)) {
      return res.status(400).json({ message: "Invalid teacherIds" });
    }

    const teachers = await User.find({ _id: { $in: teacherIds } })
      .select("fullName bio skillsOffered") // select only necessary fields
      .lean();

    res.json({ teachers });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to fetch teachers" });
  }
};

// To cancel request by the learner
export const cancelMatchRequest = async (req, res) => {
  try {
    const { requestId } = req.params;
    await MatchRequest.findByIdAndDelete(requestId);
    res.json({ message: "Request cancelled successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to cancel request." });
  }
};

// Decline (Delete) a Match Request
export const declineMatchRequest = async (req, res) => {
  try {
    const { requestId } = req.params;

    const request = await MatchRequest.findById(requestId);

    if (!request) {
      return res.status(404).json({ message: "Match request not found." });
    }

    await MatchRequest.findByIdAndDelete(requestId);

    res.status(200).json({ message: "Request declined and removed." });
  } catch (error) {
    console.error("Decline match request error:", error);
    res.status(500).json({ message: "Server error while declining request." });
  }
};

// Controller to Accept a Match Request
export const acceptRequest = async (req, res) => {
  try {
    const requestId = req.params.id;

    const request = await MatchRequest.findById(requestId);

    if (!request) {
      return res.status(404).json({ message: "Match request not found" });
    }

    request.status = "approved";
    await request.save();

    res.status(200).json({ message: "Request approved successfully" });
  } catch (error) {
    console.error("Accept Request Error:", error);
    res.status(500).json({ message: "Server Error while accepting request" });
  }
};
