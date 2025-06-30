import express from 'express';
import { protect } from '../../middleware/authMiddleware.js'; // Ensure path is correct
import {
  getMyJobs,
  createJobByEmployer,
  updateJobByEmployer,
  deleteJobByEmployer,
} from '../controllers/job.controller.js'; // Ensure this path is correct

const router = express.Router();
router.route('/jobs')
  .get(protect, getMyJobs)
  .post(protect, createJobByEmployer);
router.route('/jobs/:id')
  .put(protect, updateJobByEmployer)
  .delete(protect, deleteJobByEmployer);

export default router;