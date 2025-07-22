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
import carouselRoutes from './admin/routes/carousel.routes.js';
import OpenAI from 'openai';

// ✅ FIXED: Use official OpenAI API endpoint
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  // ❌ baseURL: "https://api.pawan.krd/v1", ← REMOVE THIS LINE
  // ✅ Official endpoint will be used by default
});

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
        "https://www.teacherjob.in",
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
app.use('/api/admin/carousel', carouselRoutes);
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


app.post('/api/generate-resume', async (req, res) => {
  const { profile } = req.body;

  if (!profile) {
    return res.status(400).json({ error: 'Profile data is required' });
  }

  try {
    const prompt = `
    You are a JSON generation machine. Your sole purpose is to convert the user's profile data into a perfectly structured JSON object based on the following rules. Failure to produce valid JSON is a critical error.

    Rules:
    1.  **Professional Summary**: Create a new top-level string field named "summary". It should be an engaging 3-4 sentence paragraph highlighting the candidate's experience, expertise, and passion for teaching.
    2.  **Headline**: Rewrite the 'headline' to be dynamic and impactful.
    3.  **Work Experience**: For each item in 'workExperience', create a 'description' array of 4-5 detailed, achievement-oriented bullet points starting with strong action verbs.
    4.  **Skills**: Restructure the flat 'skills' array into a single object with categorized keys: "technical", "teaching", and "subjectExpertise". Populate these keys with arrays of relevant skill names (as strings).

    ### CRITICAL OUTPUT FORMAT - FOLLOW EXACTLY ###
    -   **MUST** return only a raw JSON object.
    -   **NO** introductory text, explanations, or apologies.
    -   **NO** markdown formatting like \`\`\`json.
    -   **VALID SYNTAX IS MANDATORY**. Ensure all commas, brackets, and braces are correct. No trailing commas. The output is parsed programmatically.

    Input Data:
    ${JSON.stringify(profile)}
  `;

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini", // ✅ Use supported model
      messages: [{ role: "user", content: prompt }],
      temperature: 0.7,
    });

    const enhancedProfileText = response.choices[0].message.content;
    const enhancedProfileJson = JSON.parse(enhancedProfileText);

    res.json(enhancedProfileJson);

  } catch (error) {
    console.error('Error with OpenAI API:', error);
    res.status(500).json({ error: 'Failed to generate AI resume' });
  }
});

app.get("/", (req, res) => {
  res.send("API is running...");
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
