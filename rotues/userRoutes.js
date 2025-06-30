// routes/userRoutes.js
const express = require("express");
const router = express.Router();

// Import controllers
const { login, signup } = require("../controllers/Auth");

// Import middlewares
const { auth, isAdmin, isEmployer, isCollege, isEmployee } = require("../middlewares/auth");

// --- Public Routes ---
// Route for user signup
router.post("/signup", signup);
// Route for user login
router.post("/login", login);


// --- Protected Routes (for testing authorization) ---

// A generic dashboard for any authenticated user
router.get("/dashboard", auth, (req, res) => {
    res.status(200).json({
        success: true,
        message: `Welcome to the protected dashboard, ${req.user.email}! Your role is ${req.user.accountType}.`
    });
});

// Admin-specific route
router.get("/admin-panel", auth, isAdmin, (req, res) => {
    res.status(200).json({
        success: true,
        message: "Welcome to the Admin Panel!"
    });
});

// Employer-specific route
router.get("/employer-panel", auth, isEmployer, (req, res) => {
    res.status(200).json({
        success: true,
        message: "Welcome to the Employer Panel!"
    });
});

// College-specific route
router.get("/college-panel", auth, isCollege, (req, res) => {
    res.status(200).json({
        success: true,
        message: "Welcome to the College Panel!"
    });
});

// Employee-specific route
router.get("/employee-panel", auth, isEmployee, (req, res) => {
    res.status(200).json({
        success: true,
        message: "Welcome to the Employee Panel!"
    });
});


module.exports = router;