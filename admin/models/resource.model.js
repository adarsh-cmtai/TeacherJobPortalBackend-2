import mongoose from "mongoose";

const resourceSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Please add a title"],
      trim: true,
    },
    category: {
      type: String,
      required: [true, "Please add a category"],
    },
    content: {
      type: String,
      required: [true, "Please add content"],
    },
    imageUrl: {
      type: String,
      required: [true, "Please add a feature image URL"],
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User", // ✅ Correct reference to your actual User model
    },
    status: {
      type: String,
      enum: ["draft", "published"],
      default: "draft",
    },
    isFeatured: {
      type: Boolean,
      default: false,
    },
    readTime: {
      type: Number,
      required: [true, "Please add an estimated read time"],
    },
  },
  {
    timestamps: true,
  }
);

const Resource = mongoose.model("Resource", resourceSchema);
export default Resource;
