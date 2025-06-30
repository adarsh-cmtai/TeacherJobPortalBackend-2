// server.js

// 1. Configure dotenv to load environment variables at the very beginning
import dotenv from "dotenv";
dotenv.config();

// 2. Import all other necessary modules
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import connectDB from "./config/db.js";
import authRoutes from "./auth/routes/auth.routes.js";
import employerRoutes from "./employer/routes/employer.routes.js";
import collegeRoutes from "./college/routes/college.routes.js";
import adminRoutes from "./admin/routes/admin.routes.js";
import notificationRoutes from "./notifications/routes/notification.routes.js";
import contributionRoutes from "./contributions/routes/contribution.routes.js";
import salaryGuideRoutes from "./admin/routes/salaryGuide.routes.js";
import careerArticleRoutes from "./admin/routes/careerArticle.routes.js";
import publicRoutes from "./admin/routes/public.routes.js";
import publicJobRoutes from "./public/routes/job.routes.js";
import publicReviewRoutes from "./public/routes/public.routes.js";
import resourceRoute from "./admin/routes/resource.routes.js";
import pressArticle from "./admin/routes/pressArticle.routes.js";
import PostjobRoutes from "./employer/routes/Postjob.routes.js";

// Initialize database connection after loading environment variables
connectDB();

const app = express();

// --- CORS Configuration ---
app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        "http://localhost:8080",
        "https://teacher-job-frontend.vercel.app",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"]
  })
);

// ------------------------

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Register all API routes
app.use("/api/auth", authRoutes);
app.use("/api/employer", employerRoutes);
app.use("/api/college", collegeRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/notifications", notificationRoutes);
app.use("/api/contributions", contributionRoutes);
app.use("/api", publicRoutes);
app.use("/api/salary-guide", salaryGuideRoutes);
app.use("/api/career-articles", careerArticleRoutes);
app.use("/api/public", publicJobRoutes);
app.use("/api/review", publicReviewRoutes);
app.use("/api/resource", resourceRoute);
app.use("/api/press-articles", pressArticle);
app.use("/api/post-jobs", PostjobRoutes);

app.get("/", (req, res) => {
  res.send("API is running...");
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
