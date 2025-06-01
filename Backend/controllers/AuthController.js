import User from "../models/Users.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

import sendEmail from "../utils/sendEmail.js";

// Registration function

export const register = async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email already in use" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user with isVerified: false
    const user = await User.create({
      fullName,
      email,
      password: hashedPassword,
      isVerified: false,
    });

    // Generate email verification token
    const emailToken = jwt.sign(
      { userId: user._id, fullName: user.fullName },
      process.env.EMAIL_TOKEN_SECRET,
      { expiresIn: "2h" }
    );

    // Create verification link
    const verificationLink = `http://localhost:3000/verify/${emailToken}`;

    // Send email using NodeMailer
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: '"Skill Exchange" <no-reply@skillexchange.com>',
      to: email,
      subject: "Verify Your Email",
      html: `
        <h2>Welcome, ${fullName}!</h2>
        <p>Thank you for signing up. Please verify your email by clicking the link below:</p>
        <a href="${verificationLink}">Verify Email</a>
        <p>This link will expire in 15 minutes.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      message: "User created successfully. Please verify your email.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// login function
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, fullName: user.fullName },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

// forgot password function

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const token = crypto.randomBytes(32).toString("hex");
    user.resetToken = token;
    user.resetTokenExpire = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetLink = `http://localhost:3000/reset-password/${token}`;

    console.log("Sending reset email to:", user.email);

    // Send email using NodeMailer
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: '"Skill Exchange" <no-reply@skillexchange.com>',
      to: email,
      subject: "click to reset your password",
      html: `
        <a href="${resetLink}">Reset Your Password</a>
        <p>This link will expire in 15 minutes.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    // await sendEmail({
    //   to: user.email,
    //   subject: "Reset Your Password",
    //   html: `<p>Click <a href="${resetLink}">here</a> to reset your password</p>`,
    // });

    res.json({ message: "Reset link sent" });
  } catch (error) {
    console.error("Error in forgotPassword:", error);
    res.status(500).json({ message: "Something went wrong" });
  }
};

// reset password function
export const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const user = await User.findOne({
    resetToken: token,
    resetTokenExpire: { $gt: Date.now() },
  });

  if (!user)
    return res.status(400).json({ message: "Invalid or expired token" });

  const hashedPassword = await bcrypt.hash(password, 12);
  user.password = hashedPassword;
  user.resetToken = undefined;
  user.resetTokenExpire = undefined;
  await user.save();

  res.json({ message: "Password updated" });
};

// function to send verifaction Email
export const sendVerificationEmail = async (user) => {
  const token = crypto.randomBytes(32).toString("hex");
  user.resetToken = token;
  user.resetTokenExpire = Date.now() + 3600000;
  await user.save();

  const verifyLink = `http://localhost:3000/verify/${token}`;
  await sendEmail({
    to: user.email,
    subject: "Verify Your Email",
    html: `<p>Click <a href="${verifyLink}">here</a> to verify your email</p>`,
  });
};

// function to verify Email
export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const decoded = jwt.verify(token, process.env.EMAIL_TOKEN_SECRET);

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.isVerified = true;
    await user.save();

    // Create JWT token for login
    const loginToken = jwt.sign(
      { id: user._id, fullName: user.fullName },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    res.status(200).json({
      message: "Email verified successfully",
      token: loginToken,
      user: { name: user.name, email: user.email }, // optional
    });
  } catch (err) {
    return res.status(400).json({ message: "Invalid or expired token" });
  }
};
