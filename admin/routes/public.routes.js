import express from "express";
import { getAllJobs, getPublicColleges } from "../controllers/admin.controller.js";

const router = express.Router();
router.get("/jobs", getAllJobs);

router.get('/colleges', getPublicColleges); 

export default router;