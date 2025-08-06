import { User } from "../../models/User.model.js";
import { EmployerProfile } from "../../employer/models/profile.model.js";
import { CollegeProfile } from "../../college/models/profile.model.js";
import { AdminProfile } from "../../admin/models/profile.model.js";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";
import sendEmail from "../../utils/email.js";
import {
  getEmployerWelcomeTemplate,
  getEmployeeWelcomeTemplate,
} from "../../utils/emailTemplates.js";

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "30d" });
};

const generateTempToken = (userData) => {
  return jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: "15m" });
};

const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user._id, user.role);
  const options = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: 'none'
  };
  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    token,
    user: {
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      role: user.role,
    },
  });
};

const sendWelcomeEmail = async (user) => {
  try {
    const firstName = user.fullName?.split(" ")[0] || "there";
    let subject = "";
    let htmlBody = "";

    if (user.role === "employer") {
      subject = "✅ Welcome to TeacherJob.in – Let’s Build Your Career!";
      htmlBody = getEmployeeWelcomeTemplate(firstName);
    } else if (user.role === "college") {
      subject = "🏫 Welcome to TeacherJob.in — For Employers";
      htmlBody = getEmployerWelcomeTemplate(firstName);
    }

    if (subject && htmlBody) {
      await sendEmail({ email: user.email, subject, html: htmlBody });
    }
  } catch (error) {
    console.error(`Failed to send welcome email to ${user.email}:`, error);
  }
};

export const signup = async (req, res) => {
  let { fullName, email, mobile, password, confirmPassword, role, termsAccepted } = req.body;

  if (role) role = role.toLowerCase().trim();
  if (email) email = email.toLowerCase().trim();

  if (!fullName || !email || !mobile || !password || !confirmPassword || !role || !termsAccepted) {
    return res.status(400).json({ success: false, message: "Please provide all fields and accept terms" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: "Passwords do not match" });
  }

  try {
    const userExists = await User.findOne({ $or: [{ email }, { mobile }] });
    if (userExists) {
      return res.status(400).json({ success: false, message: "An account with this email or mobile already exists." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 10 * 60 * 1000;

    const message = `Welcome! Your OTP is: ${otp}. It is valid for 10 minutes.`;
    await sendEmail({
      email,
      subject: "Your Email Verification Code",
      message,
    });

    const tempToken = generateTempToken({
      fullName,
      email,
      mobile,
      password,
      role,
      termsAccepted,
      otp,
      otpExpires,
    });

    return res.status(200).json({
      success: true,
      message: `An OTP has been sent to ${email}. Please verify.`,
      tempToken,
    });
  } catch (error) {
    console.error("Signup Error:", error);
    return res.status(500).json({ success: false, message: "Server error during signup." });
  }
};

export const verifyOtp = async (req, res) => {
  const { otp } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Not authorized, no verification token" });
  }

  const token = authHeader.split(" ")[1];
  if (!otp) {
    return res.status(400).json({ success: false, message: "Please provide the OTP." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.otp !== otp || Date.now() > decoded.otpExpires) {
      return res.status(400).json({ success: false, message: "The OTP is invalid or has expired." });
    }

    const { fullName, email, mobile, password, role, termsAccepted } = decoded;

    const user = await User.create({
      fullName,
      email,
      mobile,
      password,
      role,
      termsAccepted,
      isVerified: true,
    });

    const profileData = { name: fullName, phone: mobile };

    if (role === "employer") {
      await EmployerProfile.create({ user: user._id, ...profileData });
    } else if (role === "college") {
      await CollegeProfile.create({ user: user._id, ...profileData });
    } else if (role === "admin") {
      await AdminProfile.create({ user: user._id, ...profileData });
    }

    await sendWelcomeEmail(user);
    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.error("Verify OTP Error:", error);
    return res.status(401).json({ success: false, message: "Token failed, expired, or invalid." });
  }
};
