import express from 'express';
import { getActiveJobs } from '../controllers/job.controller.js';

const router = express.Router();

router.get('/jobs', getActiveJobs);

export default router;