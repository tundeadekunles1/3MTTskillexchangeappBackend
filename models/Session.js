import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    matchRequestId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "MatchRequest",
      required: true,
    },
    teacherId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    learnerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    skill: { type: String, required: true },

    status: {
      type: String,
      enum: ["pending", "scheduled", "completed", "cancelled"],
      default: "pending",
    },
  },
  { timestamps: true }
);

export default mongoose.model("Session", sessionSchema);
