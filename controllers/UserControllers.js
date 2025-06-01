import User from "../models/Users.js";
import cloudinary from "../utils/cloudinary.js";
import jwt from "jsonwebtoken";

export const getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Server error" });
  }
};

export const updateUserProfile = async (req, res) => {
  try {
    const userId = req.user._id;
    const { skillsOffered, skillsWanted, qualification, bio } = req.body;

    const updateData = {
      skillsOffered: JSON.parse(skillsOffered),
      skillsWanted: JSON.parse(skillsWanted),
      qualification,
      bio,
      hasCompletedProfile: true, //  Mark profile as completed
    };

    // Upload to Cloudinary if a file is present
    if (req.file && req.file.path) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "profile_pics",
      });
      updateData.profilePicUrl = result.secure_url;
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
    });

    // Generate new JWT with updated profile completion
    const token = jwt.sign(
      {
        id: updatedUser._id,
        email: updatedUser.email,
        fullName: updatedUser.fullName,
        hasCompletedProfile: updatedUser.hasCompletedProfile,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    return res.status(200).json({
      message: "Profile updated successfully",
      token,
    });
  } catch (err) {
    console.error("Error updating profile:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

export const getSkillMatches = async (req, res) => {
  try {
    const currentUserId = req.user.id;
    const currentUser = await User.findById(currentUserId);

    if (!currentUser || !currentUser.skillsWanted.length) {
      return res.status(400).json({ message: "No skillsWanted specified." });
    }

    const matches = await User.find({
      _id: { $ne: currentUserId }, // exclude current user
      skillsOffered: { $in: currentUser.skillsWanted }, // anyone offering what I want
    }).select("fullName skillsOffered skillsWanted profilePicUrl bio");

    res.status(200).json(matches);
  } catch (err) {
    console.error("Error fetching matches:", err);
    res.status(500).json({ message: "Server error while fetching matches" });
  }
};

export const getAllTeachers = async (req, res) => {
  try {
    const teachers = await User.find({
      skillsOffered: { $exists: true, $ne: [] },
    }).select("_id fullName");
    res.json({ teachers });
  } catch (error) {
    res.status(500).json({ message: "Server error fetching teachers" });
  }
};

export const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId).select("fullName profilePicUrl");

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    res.status(200).json(user);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
};
