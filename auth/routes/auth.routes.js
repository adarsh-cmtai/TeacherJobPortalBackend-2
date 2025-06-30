// routes/auth.routes.js

import express from "express";
import {
  signup,
  login,
  logout,
  getMe,
  updatePassword,
  deleteAccount,
  googleLogin,
  // --- Add new imports ---
  verifyOtp,
  forgotPassword,
  resetPassword,
} from "../controllers/auth.controller.js";
import { protect } from "../../middleware/authMiddleware.js";

const router = express.Router();

// --- Public Authentication Routes ---
router.post("/signup", signup);
router.post("/verify-otp", verifyOtp); // New route for OTP verification
router.post("/login", login);
router.post("/google", googleLogin);
router.post("/forgot-password", forgotPassword); // New route for forgot password
router.patch("/reset-password/:token", resetPassword); // New route for resetting password

// --- Protected Routes (require user to be logged in) ---
router.get("/logout", logout);
router.get("/me", protect, getMe);
router.put("/updatepassword", protect, updatePassword);
router.delete("/deleteaccount", protect, deleteAccount);

export default router;
