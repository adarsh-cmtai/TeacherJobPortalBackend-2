import mongoose from "mongoose";

const pressArticleSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Article title is required"],
      trim: true,
      unique: true,
    },
    slug: {
      type: String,
      // required: true, // ✅ FIX: REMOVE THIS LINE
      unique: true,
      // Add a sparse index to allow multiple nulls before the slug is generated
      sparse: true,
    },
    publication: {
      type: String,
      required: [true, "Publication name is required"],
      trim: true,
    },
    date: {
      type: Date,
      default: Date.now,
    },
    snippet: {
      type: String,
      required: [true, "A short snippet is required"],
    },
    imageUrl: {
      type: String,
      required: [true, "An image URL from S3 is required"],
    },
    s3Key: {
      type: String,
      required: true,
    },
    fullContent: {
      type: [String],
      default: [],
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// This middleware will now work correctly because the field is no longer required upon creation.
pressArticleSchema.pre("save", function (next) {
  if (this.isModified("title")) {
    this.slug = this.title
      .toLowerCase()
      .split(" ")
      .join("-")
      .replace(/[^\w-]+/g, "");
  }
  next();
});

pressArticleSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

const PressArticle = mongoose.model("PressArticle", pressArticleSchema);

export default PressArticle;
