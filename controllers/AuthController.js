import User from "../models/Users.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";
dotenv.config();

const API_BASE_URL = process.env.API_BASE_URL;
console.log(API_BASE_URL);

dotenv.config();

// Helper function for sending emails to reduce repetition
const sendEmailHelper = async (to, subject, htmlContent, expiryMessage) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: '"Skill Bridge" <no-reply@skillbridge.com>',
      to: to,
      subject: subject,
      html: `
        ${htmlContent}
        <p>${expiryMessage}</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${to} for subject: ${subject}`);
  } catch (error) {
    console.error(`Error sending email to ${to}:`, error);
    throw new Error("Failed to send email"); // Re-throw to be caught by the calling function
  }
};

// Registration function
export const register = async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      // Check if already verified, if so, inform user.
      if (existingUser.isVerified) {
        return res
          .status(400)
          .json({ message: "Email already in use and verified." });
      }

      return res.status(400).json({
        message:
          "Email already in use. Please check your email for verification or log in.",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate 8-character UUID for verification token
    const verificationToken = uuidv4().substring(0, 8);

    // Create user with isVerified: false
    const user = await User.create({
      fullName,
      email,
      password: hashedPassword,
      isVerified: false,
      verificationToken,
    });

    // Create verification link
    const verificationLink = `${API_BASE_URL}/verify/${verificationToken}`;

    // Send email using the helper
    await sendEmailHelper(
      email,
      "Verify Your Email",
      `<h2>Welcome, ${fullName}!</h2><p>Thank you for signing up on SkillBridge.</p><a href="${verificationLink}">Verify Email</a>`,
      "This link will expire in 15 minutes."
    );

    res.status(201).json({
      message: "User created successfully. Please verify your email.",
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ message: "Server error during registration." });
  }
};

// Verify Email function
export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;
    console.log("Verify Email: Received token:", token);

    // Find user by EXACT token match
    const user = await User.findOne({
      verificationToken: token, // Exact match for UUID substring
    });

    if (!user) {
      console.log("Verify Email: Invalid or expired token (User not found).");
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Check if already verified
    if (user.isVerified) {
      console.log("Verify Email: Email already verified.");
      return res
        .status(400)
        .json({ message: "Email already verified. Please log in." });
    }

    // Mark as verified and clear token
    user.isVerified = true;
    user.verificationToken = null; //  to explicitly remove the field
    await user.save();

    console.log("Verify Email: User successfully marked as verified.");

    // Generate login token (with shorter expiry for initial login)
    const loginToken = jwt.sign(
      {
        id: user._id,
        email: user.email,
        fullName: user.fullName,
        hasCompletedProfile: user.hasCompletedProfile,
      }, // Include hasCompletedProfile for immediate use on login
      process.env.JWT_SECRET,
      { expiresIn: "15m" } // Shorter expiry for security after email verification
    );

    res.status(200).json({
      message: "Email verified successfully",
      token: loginToken,
      user: {
        name: user.fullName,
        email: user.email,
        hasCompletedProfile: user.hasCompletedProfile,
      },
    });
  } catch (err) {
    console.error("Verify Email Error:", err);
    res
      .status(500)
      .json({ message: "Verification failed due to server error." });
  }
};

// Login function
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    // Ensure user is verified before logging in
    if (!user.isVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email before logging in." });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        fullName: user.fullName,
        hasCompletedProfile: user.hasCompletedProfile,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d", // Standard expiry for logged-in sessions
      }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        fullName: user.fullName,
        email: user.email,
        hasCompletedProfile: user.hasCompletedProfile,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login." });
  }
};

// Forgot Password controller with UUID shortening
export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate 8-character UUID token
    const token = uuidv4().substring(0, 8);
    user.resetToken = token;
    user.resetTokenExpire = Date.now() + 3600000; // 1 hour expiry
    await user.save();

    // Create reset link
    const resetLink = `${API_BASE_URL}/verify/${token}`;

    // Send email using the helper
    await sendEmailHelper(
      email,
      "Reset Your Password",
      `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
      "This link will expire in 1 hour." // Match the 1 hour expiry
    );

    res.json({ message: "Password reset link sent to your email." });
  } catch (error) {
    console.error("Error in forgotPassword:", error);
    res
      .status(500)
      .json({ message: "Server error during password reset request." });
  }
};

// Reset Password controller with UUID shortening
export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    // Find user by EXACT token match and check expiry
    const user = await User.findOne({
      resetToken: token, // Exact match for UUID substring
      resetTokenExpire: { $gt: Date.now() }, // Token must not be expired
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 12);
    user.password = hashedPassword;
    user.resetToken = null; // Clear token after use
    user.resetTokenExpire = null; // Clear expiry after use
    await user.save();

    res.json({ message: "Password updated successfully." });
  } catch (error) {
    console.error("Error in resetPassword:", error);
    res.status(500).json({ message: "Server error during password reset." });
  }
};
