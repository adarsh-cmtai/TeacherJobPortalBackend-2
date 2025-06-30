import express from 'express';
import multer from 'multer'; // ✅ Step 1: Import multer here
import {
  getAllPressArticles,
  getPressArticleById,
  createPressArticle,
  updatePressArticle,
  deletePressArticle,
} from '../controllers/pressArticle.controller.js';

const router = express.Router();

const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 5 } // 5MB limit
});


router.get("/", getAllPressArticles);
router.get("/:id", getPressArticleById);

router.post("/", upload.single('imageUrl'), createPressArticle);
router.put("/:id", upload.single('imageUrl'), updatePressArticle);
router.delete("/:id", deletePressArticle);

export default router;