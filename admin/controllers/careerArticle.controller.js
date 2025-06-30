import { CareerArticle } from "../models/careerArticle.model.js";
import { uploadOnS3, deleteFromS3 } from "../../config/s3Config.js";

export const createArticle = async (req, res) => {
  try {
    const { title, slug, summary, content, category, author } = req.body;
    const file = req.file;

    if (!file) {
      return res
        .status(400)
        .json({ success: false, message: "A featured image is required." });
    }

    const imageUploadResult = await uploadOnS3(
      file.buffer,
      "career-articles",
      file.mimetype
    );

    const newArticle = await CareerArticle.create({
      title,
      slug,
      summary,
      content,
      category,
      author,
      image: imageUploadResult,
    });
    res.status(201).json({ success: true, data: newArticle });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

export const getAllArticles = async (req, res) => {
  try {
    let query = {};
    if (req.query.category) {
      query.category = req.query.category;
    }
    const articles = await CareerArticle.find(query).sort({ createdAt: -1 });
    res
      .status(200)
      .json({ success: true, count: articles.length, data: articles });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const getArticleBySlug = async (req, res) => {
  try {
    const article = await CareerArticle.findOne({ slug: req.params.slug });
    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Article not found." });
    }
    res.status(200).json({ success: true, data: article });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const updateArticle = async (req, res) => {
  try {
    const existingArticle = await CareerArticle.findById(req.params.id);
    if (!existingArticle) {
      return res
        .status(404)
        .json({ success: false, message: "Article not found." });
    }

    const updatedData = { ...req.body };
    const file = req.file;

    if (file) {
      if (existingArticle.image && existingArticle.image.public_id) {
        await deleteFromS3(existingArticle.image.public_id);
      }
      const imageUploadResult = await uploadOnS3(
        file.buffer,
        "career-articles",
        file.mimetype
      );
      updatedData.image = imageUploadResult;
    }

    const article = await CareerArticle.findByIdAndUpdate(
      req.params.id,
      updatedData,
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({ success: true, data: article });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

export const deleteArticle = async (req, res) => {
  try {
    const article = await CareerArticle.findById(req.params.id);
    if (!article) {
      return res
        .status(404)
        .json({ success: false, message: "Article not found." });
    }

    if (article.image && article.image.public_id) {
      await deleteFromS3(article.image.public_id);
    }

    await CareerArticle.findByIdAndDelete(req.params.id);

    res
      .status(200)
      .json({ success: true, message: "Article deleted successfully." });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};