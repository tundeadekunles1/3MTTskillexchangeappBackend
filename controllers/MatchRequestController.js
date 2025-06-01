import MatchRequest from "../models/MatchRequest.js";

export const approveMatchRequest = async (req, res) => {
  try {
    const matchRequest = await MatchRequest.findById(req.params.id)
      .populate("learnerId", "fullName")
      .populate("teacherId", "fullName");

    if (!matchRequest) {
      return res.status(404).json({ message: "Match request not found" });
    }

    matchRequest.status = "approved";
    await matchRequest.save();

    res.status(200).json({ message: "Match request approved successfully" });
  } catch (error) {
    console.error("Error approving match request:", error);
    res.status(500).json({ message: "Internal Server Error", error });
  }
};

export const getApprovedMatchByParticipant = async (req, res) => {
  try {
    const matches = await MatchRequest.find({
      $or: [{ teacherId: req.params.userId }, { learnerId: req.params.userId }],
      status: "approved",
    })
      .sort({ createdAt: -1 })
      .limit(1)
      .populate("teacherId", "fullName avatar")
      .populate("learnerId", "fullName avatar");

    if (!matches || matches.length === 0) {
      return res.status(404).json({
        success: false,
        error: "No approved matches found",
      });
    }

    res.status(200).json({
      success: true,
      data: matches[0],
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Server error",
    });
  }
};

export const getMatchRequestById = async (req, res) => {
  try {
    const matchRequest = await MatchRequest.findById(req.params.id)
      .populate("teacherId", "fullName profilePicUrl")
      .populate("learnerId", "fullName profilePicUrl");

    if (!matchRequest) {
      return res
        .status(404)
        .json({ success: false, error: "Match request not found" });
    }

    res.status(200).json({ success: true, data: matchRequest });
  } catch (error) {
    console.error("Error fetching match request:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
};
