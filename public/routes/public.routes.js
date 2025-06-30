import express from 'express';
// import { getActiveJobs } from '../controllers/job.controller.js';
// import { getPublicColleges } from '../../admin/controllers/admin.controller.js';
import { getReviewsByCollege } from '../controllers/review.controller.js';

const router = express.Router();

// router.get('/jobs', getActiveJobs);
// router.get('/colleges', getPublicColleges);
router.get('/reviews/:collegeId', getReviewsByCollege);

export default router;