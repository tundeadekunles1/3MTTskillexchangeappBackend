import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  resetToken: String,
  resetTokenExpire: Date,
  isVerified: {
    type: Boolean,
    default: false,
  },
  skillsOffered: [{ type: String }],
  skillsWanted: [{ type: String }],
  qualification: String,
  bio: String,
  profilePicUrl: {
    type: String,
    default: "",
  },
  hasCompletedProfile: {
    type: Boolean,
    default: false,
  },
  verificationToken: { type: String },
});

const User = mongoose.model("User", userSchema);

export default User;
