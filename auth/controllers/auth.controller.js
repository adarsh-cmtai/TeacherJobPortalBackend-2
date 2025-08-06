// Imports (as per your existing structure)
import { User } from "../../models/User.model.js";
import jwt from "jsonwebtoken";
import sendEmail from "../../utils/email.js";

// Token generators
const generateToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "30d" });
};

const generateTempToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "15m" });
};

// Token response
const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user._id, user.role);
  res
    .status(statusCode)
    .cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "none",
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    })
    .json({
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

// Signup handler
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

    if (userExists && userExists.isVerified) {
      return res.status(400).json({ success: false, message: "Account already exists." });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 10 * 60 * 1000;

    let user;
    if (userExists && !userExists.isVerified) {
      user = userExists;
      user.fullName = fullName;
      user.email = email;
      user.mobile = mobile;
      user.password = password;
      user.role = role;
      user.termsAccepted = termsAccepted;
      user.otp = otp;
      user.otpExpires = otpExpires;
    } else {
      user = new User({
        fullName,
        email,
        mobile,
        password,
        role,
        termsAccepted,
        otp,
        otpExpires,
      });
    }

    await user.save();

    await sendEmail({
      email,
      subject: "Your OTP Code",
      message: `Your OTP is ${otp}. It will expire in 10 minutes.`,
    });

    const tempToken = generateTempToken(user._id);
    return res.status(200).json({
      success: true,
      message: `OTP sent to ${email}`,
      tempToken,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || "Signup error" });
  }
};

// OTP verification handler
export const verifyOtp = async (req, res) => {
  const { otp } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findOne({
      _id: decoded.id,
      otp,
      otpExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    sendTokenResponse(user, 200, res);
  } catch (err) {
    return res.status(401).json({ success: false, message: "Token invalid or expired" });
  }
};
