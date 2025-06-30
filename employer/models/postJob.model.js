import mongoose from "mongoose";

const postJobSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Job title is required."],
      trim: true,
    },
    location: {
      type: String,
      required: [true, "Location is required."],
      trim: true,
    },
    jobType: {
      type: String,
      required: [true, "Job type is required."],
      enum: ["Full-time", "Part-time", "Contract"],
    },
    category: {
      type: String,
      required: [true, "Category is required."],
      trim: true,
    },
    description: {
      type: String,
      required: [true, "Description is required."],
    },
    experienceLevel: {
      type: String,
      required: [true, "Experience level is required."],
      enum: ["Entry-level", "Mid-level", "Senior-level"],
    },
    yearsOfExperience: {
      type: Number,
      required: [true, "Years of experience is required."],
    },
    requiredSkills: {
      type: [String],
      required: true,
    },
    schoolName: {
      type: String,
      required: true,
    },
    postedBy: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User",
    },
    status: {
      type: String,
      required: true,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
  },
  {
    timestamps: true,
  }
);

const PostJob = mongoose.model("PostJob", postJobSchema);

export default PostJob;