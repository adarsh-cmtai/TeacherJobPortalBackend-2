import PressArticle from "../models/pressArticle.model.js";
import { uploadOnS3, deleteFromS3 } from "../../config/s3Config.js";

// ===================================
// CREATE a new press article
// ===================================
export const createPressArticle = async (req, res) => {
  const { title, publication, snippet, fullContent, date } = req.body;

  if (!req.file) {
    return res
      .status(400)
      .json({ success: false, message: "Image file is required" });
  }
  if (!title || !publication || !snippet) {
    return res
      .status(400)
      .json({
        success: false,
        message: "Title, publication, and snippet are required",
      });
  }

  try {
    const s3UploadResult = await uploadOnS3(
      req.file.buffer,
      "press-articles",
      req.file.mimetype
    );

    // FIX: Use .save() to trigger the 'pre' middleware for slug generation
    const article = new PressArticle({
      title,
      publication,
      snippet,
      imageUrl: s3UploadResult.url,
      s3Key: s3UploadResult.public_id,
      fullContent: fullContent ? JSON.parse(fullContent) : [snippet],
      date,
    });

    // This .save() command will now correctly trigger the pre('save') hook
    await article.save();

    res.status(201).json({
      success: true,
      data: article,
      message: "Article created successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to create article: " + error.message,
    });
  }
};

// ===================================
// UPDATE an existing article by ID
// ===================================
export const updatePressArticle = async (req, res) => {
  try {
    const article = await PressArticle.findById(req.params.id);
    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });
    }

    const { title, publication, snippet, fullContent, date } = req.body;
    let imageUrl = article.imageUrl;
    let s3Key = article.s3Key;

    if (req.file) {
      if (article.s3Key) {
        await deleteFromS3(article.s3Key);
      }
      const s3UploadResult = await uploadOnS3(
        req.file.buffer,
        "press-articles",
        req.file.mimetype
      );
      imageUrl = s3UploadResult.url;
      s3Key = s3UploadResult.public_id;
    }

    // Update the fields
    article.title = title || article.title;
    article.publication = publication || article.publication;
    article.snippet = snippet || article.snippet;
    article.fullContent = fullContent
      ? JSON.parse(fullContent)
      : article.fullContent;
    article.date = date || article.date;
    article.imageUrl = imageUrl;
    article.s3Key = s3Key;

    // The .save() will also trigger the pre('save') hook if the title is modified
    const updatedArticle = await article.save();

    res.status(200).json({
      success: true,
      data: updatedArticle,
      message: "Article updated successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to update article: " + error.message,
    });
  }
};

// ===================================
// DELETE an article by ID
// ===================================
export const deletePressArticle = async (req, res) => {
  try {
    const article = await PressArticle.findByIdAndDelete(req.params.id);
    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });
    }
    if (article.s3Key) {
      await deleteFromS3(article.s3Key);
    }
    res
      .status(200)
      .json({ success: true, message: "Article deleted successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Server Error: " + error.message });
  }
};

// ===================================
// GET ALL articles
// ===================================
export const getAllPressArticles = async (req, res) => {
  try {
    const articles = await PressArticle.find({}).sort({ date: -1 });
    res
      .status(200)
      .json({ success: true, count: articles.length, data: articles });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Server Error: " + error.message });
  }
};

// ===================================
// GET ONE article by ID
// ===================================
export const getPressArticleById = async (req, res) => {
  try {
    const article = await PressArticle.findById(req.params.id);
    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Article not found" });
    }
    res.status(200).json({ success: true, data: article });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Server Error: " + error.message });
  }
};
