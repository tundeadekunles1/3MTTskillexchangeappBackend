import mongoose from "mongoose";

const classSessionSchema = new mongoose.Schema({
  date: {
    type: Date,
    required: true,
  },
  originalDate: {
    type: Date,
    required: true,
  },

  status: {
    type: String,
    enum: ["scheduled", "completed", "cancelled", "rescheduled"],
    default: "scheduled",
  },
  notes: {
    type: String,
    default: "",
  },
  materialsCovered: [
    {
      topic: String,
      resources: [String], // URLs or references to learning materials
    },
  ],
  attendance: {
    teacher: {
      type: Boolean,
      default: false,
    },
    learner: {
      type: Boolean,
      default: false,
    },
  },
  roomUrl: { type: String },
});

const sessionScheduleSchema = new mongoose.Schema(
  {
    sessionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Session",
      required: true,
    },
    status: {
      type: String,
      enum: ["scheduled", "completed", "cancelled", "rescheduled"],
      default: "scheduled",
    },
    startDate: {
      type: Date,
      required: true,
    },
    totalWeeks: {
      type: Number,
      required: true,
      min: 1,
    },
    sessionsPerWeek: {
      type: Number,
      required: true,
      min: 1,
      max: 7,
    },
    preferredDays: {
      type: [Number], // 0-6 (Sunday-Saturday)
      required: true,
    },
    timeSlot: {
      startTime: { type: String, required: true },
      endTime: { type: String, required: true },
    },
    allSessions: [classSessionSchema], // All individual class sessions
    progress: {
      completionPercentage: {
        type: Number,
        default: 0,
        min: 0,
        max: 100,
      },
      lastUpdated: {
        type: Date,
        default: Date.now,
      },
    },
    cancellationHistory: [
      {
        date: Date,
        reason: String,
        rescheduledTo: Date,
      },
    ],
    rescheduleHistory: [
      {
        originalDate: Date,
        newDate: Date,
        reason: String,
      },
    ],
  },

  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Calculate progress before saving
sessionScheduleSchema.pre("save", function (next) {
  if (this.allSessions && this.allSessions.length > 0) {
    const completed = this.allSessions.filter(
      (s) => s.status === "completed"
    ).length;
    this.progress.completionPercentage = Math.round(
      (completed / this.allSessions.length) * 100
    );
    this.progress.lastUpdated = new Date();
  }
  next();
});

// Add text index for search
sessionScheduleSchema.index({
  "materialsCovered.topic": "text",
  notes: "text",
});

export default mongoose.model("SessionSchedule", sessionScheduleSchema);
