import express from "express";
import {
  createSalaryGuide,
  getAllSalaryGuides,
  getSalaryGuideById,
  updateSalaryGuide,
  deleteSalaryGuide,
} from "../controllers/salaryGuide.controller.js";

const router = express.Router();
router.get("/", getAllSalaryGuides);
router.get("/:id", getSalaryGuideById);

router.post("/", createSalaryGuide);

router.route("/:id").put(updateSalaryGuide).delete(deleteSalaryGuide);

export default router;