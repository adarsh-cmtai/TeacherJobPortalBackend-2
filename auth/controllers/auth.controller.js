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
import bcrypt from "bcrypt";
import mongoose from "mongoose";

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, {
    expiresIn: "30d",
  });
};

const generateTempToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
};

const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user._id, user.role);
  const options = {
    expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: 'none'
  };
  res
    .status(statusCode)
    .cookie("token", token, options)
    .json({
      success: true,
      token: token,
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
      await sendEmail({
        email: user.email,
        subject: subject,
        html: htmlBody,
      });
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
    return res.status(400).json({
      success: false,
      message: "Please provide all fields and accept terms",
    });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: "Passwords do not match" });
  }

  try {
    const userExists = await User.findOne({ $or: [{ email }, { mobile }], isVerified: true });

    if (userExists) {
      return res.status(400).json({
        success: false,
        message: "An account with this email or mobile already exists.",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const tempUserData = {
      fullName,
      email,
      mobile,
      password: hashedPassword,
      role,
      termsAccepted,
      otp,
    };

    const tempToken = generateTempToken(tempUserData);
    
    const message = `Welcome! Your OTP is: ${otp}. It is valid for 15 minutes.`;
    await sendEmail({
      email: email,
      subject: "Your Email Verification Code",
      message,
    });

    return res.status(200).json({
      success: true,
      message: `An OTP has been sent to ${email}. Please verify.`,
      tempToken: tempToken,
    });
  } catch (error) {
    console.error("Signup Error:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Server error during signup.",
    });
  }
};

export const verifyOtp = async (req, res) => {
  const { otp } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Not authorized, no verification token",
    });
  }
  const token = authHeader.split(" ")[1];

  if (!otp) {
    return res.status(400).json({ success: false, message: "Please provide the OTP." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.otp !== otp) {
      return res.status(400).json({
        success: false,
        message: "The OTP is invalid or has expired.",
      });
    }

    const { fullName, email, mobile, password, role, termsAccepted } = decoded;

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({
        success: false,
        message: "An account with this email already exists.",
      });
    }
    
    const newUserId = new mongoose.Types.ObjectId();

    await User.collection.insertOne({
        _id: newUserId,
        fullName,
        email,
        mobile,
        password,
        role,
        termsAccepted,
        isVerified: true,
        createdAt: new Date(),
        updatedAt: new Date()
    });

    const user = await User.findById(newUserId);

    if (!user) {
        throw new Error('Failed to create user account after verification.');
    }

    const profileData = { name: fullName, phone: mobile, user: user._id };
    if (role === "employer") {
      await EmployerProfile.create(profileData);
    } else if (role === "college") {
      await CollegeProfile.create(profileData);
    } else if (role === "admin") {
      await AdminProfile.create(profileData);
    }

    await sendWelcomeEmail(user);

    sendTokenResponse(user, 201, res);
  } catch (error) {
    console.error("Verify OTP Error:", error);
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        return res.status(401).json({ success: false, message: "Verification failed. The session may have expired. Please sign up again." });
    }
    res.status(500).json({ success: false, message: "An error occurred during verification." });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Please provide email and password" });
  }
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select("+password");
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }
    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: "Account not verified. Please check your email for a verification code.",
      });
    }
    sendTokenResponse(user, 200, res);
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ success: false, message: "Server error during login." });
  }
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(200).json({
        success: true,
        message: "If an account exists, a reset link has been sent.",
      });
    }
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const message = `You requested a password reset. Click this link to set a new password: ${resetURL}\nThis link is valid for 10 minutes. If you did not request this, please ignore this email.`;

    await sendEmail({
      email: user.email,
      subject: "Your Password Reset Link",
      message,
    });

    res.status(200).json({
      success: true,
      message: "Password reset link has been sent to your email!",
    });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.status(500).json({ success: false, message: "Error sending email." });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto.createHash("sha256").update(req.params.token).digest("hex");
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: "Token is invalid or has expired." });
    }

    const { password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: "Passwords do not match." });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters long.",
      });
    }

    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password has been reset successfully. Please log in.",
    });
  } catch (error) {
    console.error("Critical Reset Password Error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error during password reset.",
    });
  }
};

export const googleLogin = async (req, res) => {
  const { token, role } = req.body;
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const { email, name, picture } = ticket.getPayload();
    let user = await User.findOne({ email });

    if (user) {
      if (!user.isVerified) {
        user.isVerified = true;
        await user.save();
      }
      sendTokenResponse(user, 200, res);
    } else {
      if (!role) {
        return res.status(400).json({
          success: false,
          message: "Role is required for new user signup.",
        });
      }
      const randomPassword = crypto.randomBytes(16).toString("hex");

      user = await User.create({
        fullName: name,
        email,
        password: randomPassword,
        role,
        termsAccepted: true,
        isVerified: true,
      });

      if (role === "employer") {
        await EmployerProfile.create({
          user: user._id,
          name,
          profilePicture: { url: picture },
        });
      } else if (role === "college") {
        await CollegeProfile.create({
          user: user._id,
          name,
          logo: { url: picture },
        });
      } else {
        return res.status(400).json({ success: false, message: "Invalid role for Google signup." });
      }
      
      await sendWelcomeEmail(user);
      sendTokenResponse(user, 201, res);
    }
  } catch (error) {
    console.error("Google Login Error:", error);
    res.status(500).json({ success: false, message: "Google Sign-In failed." });
  }
};

export const logout = (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: 'none',
    path: '/'
  });
  res.status(200).json({ success: true, message: 'Logged out successfully' });
};

export const getMe = async (req, res) => {
  try {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ success: false, message: "Not authorized, no user found" });
    }
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }
    res.status(200).json({
      success: true,
      data: {
        id: user._id,
        email: user.email,
        role: user.role,
        fullName: user.fullName,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server Error" });
  }
};

export const updatePassword = async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(401).json({ success: false, message: "Not authorized" });
  }
  const { currentPassword, newPassword } = req.body;
  try {
    const user = await User.findById(req.user.id).select("+password");
    if (!(await user.comparePassword(currentPassword))) {
      return res.status(401).json({ success: false, message: "Incorrect current password" });
    }
    user.password = newPassword;
    await user.save();
    res.status(200).json({ success: true, message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const deleteAccount = async (req, res) => {
  if (!req.user || !req.user.id) {
    return res.status(401).json({ success: false, message: "Not authorized" });
  }
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({
      success: false,
      message: "Password is required to delete your account",
    });
  }
  try {
    const user = await User.findById(req.user.id).select("+password");
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    if (user.role === "employer") {
      await EmployerProfile.deleteOne({ user: req.user.id });
    } else if (user.role === "college") {
      await CollegeProfile.deleteOne({ user: req.user.id });
    }

    await user.deleteOne();

    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: 'none',
      path: '/'
    });
    res.status(200).json({
      success: true,
      message: "Your account has been deleted successfully",
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
