import express from "express";
import {
  createArticle,
  getAllArticles,
  getArticleBySlug,
  updateArticle,
  deleteArticle,
} from "../controllers/careerArticle.controller.js";
import { singleUpload } from "../../middleware/multer.js";

const router = express.Router();

router.get("/", getAllArticles);
router.get("/:slug", getArticleBySlug);

router.post("/", singleUpload, createArticle);

router.put("/:id", singleUpload, updateArticle);
router.delete("/:id", deleteArticle);

export default router;