// admin/routes/resource.routes.js

import express from "express";
import {
  createResource,
  updateResource,
  deleteResource,
  getResources,
  getResourceById,
} from "../controllers/resource.controller.js";
import { protect, restrictTo } from "../../middleware/authMiddleware.js";

// --- CHANGES START HERE ---

// 1. Import the multer library
import multer from "multer";
const upload = multer({ storage: multer.memoryStorage() });

// --- CHANGES END HERE ---

const router = express.Router();

router.route("/").get(getResources);
router.route("/:id").get(getResourceById);

// This part of your code is already correct and uses the new 'upload' instance
router
  .route("/")
  .post(protect, restrictTo("Admin"), upload.single("image"), createResource);

router
  .route("/:id")
  .put(protect, restrictTo("Admin"), upload.single("image"), updateResource)
  .delete(protect, restrictTo("Admin"), deleteResource);

export default router;
