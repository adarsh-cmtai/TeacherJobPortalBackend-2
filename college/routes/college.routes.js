import express from 'express';
import { protect, restrictTo } from '../../middleware/authMiddleware.js';
import { upload } from '../../middleware/multer.js';
import {
    getMyCollegeProfile, updateMyCollegeProfile, updateMyCollegeSettings, createJobPost, getMyPostedJobs,
    getJobByIdForCollege, updateMyJob, deleteMyJob, getApplicationsForMyJobs,
    getShortlistedApplications, getOfferStageApplications, updateApplicationStatusByCollege,
    scheduleInterview, updateStatusAfterInterview, finalizeHiring
} from '../controllers/college.controller.js';

const router = express.Router();
router.use(protect, restrictTo('college'));

router.route('/profile').get(getMyCollegeProfile).put(updateMyCollegeProfile);
router.put('/settings', updateMyCollegeSettings);

router.route('/jobs').post(createJobPost).get(getMyPostedJobs);
router.route('/jobs/:jobId').get(getJobByIdForCollege).put(updateMyJob).delete(deleteMyJob);

router.get('/applications', getApplicationsForMyJobs);
router.get('/applications/shortlisted', getShortlistedApplications);
router.get('/applications/offers', getOfferStageApplications);
router.put('/applications/:appId/status', updateApplicationStatusByCollege);
router.put('/applications/:appId/schedule-interview', scheduleInterview);
router.put('/applications/:appId/update-status', upload.single('offerLetter'), updateStatusAfterInterview);
router.put('/applications/:appId/finalize-hiring', finalizeHiring);

export default router;