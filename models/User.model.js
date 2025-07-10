import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    mobile: {
      type: String,
      required: false,
      unique: true,
      trim: true,
      sparse: true,
    },
    password: { 
      type: String, 
      required: true, 
      select: false 
    },
    role: {
      type: String,
      enum: ["employee", "employer", "admin", "college"],
      required: true,
    },
    termsAccepted: { 
      type: Boolean, 
      required: true, 
      default: false 
    },
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

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

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
