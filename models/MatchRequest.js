import mongoose from "mongoose";

const matchRequestSchema = new mongoose.Schema(
  {
    learnerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    teacherId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    skill: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ["pending", "approved"],
      default: "pending",
    },
  },
  { timestamps: true }
);

// Index for faster queries
matchRequestSchema.index({
  teacherId: 1,
  learnerId: 1,
  status: 1,
});

const MatchRequest = mongoose.model("MatchRequest", matchRequestSchema);
export default MatchRequest;
