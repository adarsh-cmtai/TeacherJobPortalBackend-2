// models/User.model.js

import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true, select: false },
    role: {
      type: String,
      enum: ["employee", "employer", "admin", "college"],
      required: true,
    },
    termsAccepted: { type: Boolean, required: true, default: false },

    // --- New Fields for Verification and Password Reset ---
    isVerified: {
      type: Boolean,
      default: false,
    },
    otp: {
      type: String,
      select: false,
    },
    otpExpires: {
      type: Date,
      select: false,
    },
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpires: {
      type: Date,
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Method to compare entered password with the hashed one
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to generate a password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // Expires in 10 minutes

  return resetToken; // Return the unhashed token to be sent via email
};

// --- Virtuals (No changes needed here) ---
userSchema.virtual("employerProfile", {
  ref: "EmployerProfile",
  localField: "_id",
  foreignField: "user",
  justOne: true,
});

userSchema.virtual("collegeProfile", {
  ref: "CollegeProfile",
  localField: "_id",
  foreignField: "user",
  justOne: true,
});

userSchema.virtual("adminProfile", {
  ref: "AdminProfile",
  localField: "_id",
  foreignField: "user",
  justOne: true,
});

export const User = mongoose.model("User", userSchema);
