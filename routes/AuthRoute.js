import express from "express";
import { authenticate } from "../middlewares/AuthMiddlewares.js";
import upload from "../middlewares/Upload.js";
import { updateUserProfile } from "../controllers/UserControllers.js";

const router = express.Router();
import {
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyEmail,
} from "../controllers/AuthController.js";

router.post("/register", register);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);
router.get("/verify-email/:token", verifyEmail);
router.patch(
  "/update-profile",
  authenticate,
  upload.single("profilePic"),
  updateUserProfile
);

export default router;
