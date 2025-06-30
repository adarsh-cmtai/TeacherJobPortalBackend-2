import express from 'express';
import { protect, restrictTo } from '../../middleware/authMiddleware.js';
import {
    getDashboardStats,
    manageJobPosts,
    getAllJobs,
    getFullEmployerDetails,
    getFullCollegeDetails,
    forwardInterviewToEmployer,
    forwardOfferToEmployer,
    getAllUsersByRole,
    createJobByAdmin,
    updateJobByAdmin,
    deleteJobByAdmin,
    getWorkflowApplications,
    getAllUsers,
    getFullUserDetails,
    updateUserStatus,
    getMyAdminProfile,
    updateMyAdminProfile,
    deleteUserByAdmin,
    updateCollegeProfileByAdmin,
    updateEmployerProfileByAdmin,
    getAllApplications,
    getJobDetailsForAdmin,
    updateApplicationByAdmin,
    getPendingApplications,
    getPendingJobs,
    getCollegeListForAdmin,
    getPendingDocumentApplications,
    verifyDocuments,
    getInterviewApplications
} from '../controllers/admin.controller.js';
import { createReviewByAdmin, getAllReviews, updateReview, deleteReview } from '../controllers/admin.review.controller.js';
import { agreementUpload } from '../../middleware/multer.js';

const router = express.Router();

router.use(protect, restrictTo('Admin'));

router.get('/stats', getDashboardStats);

router.route('/profile')
    .get(getMyAdminProfile)
    .put(updateMyAdminProfile);

router.route('/jobs')
    .get(getAllJobs)  
    .post(createJobByAdmin);

router.get('/jobs/pending-approval', getPendingJobs);

router.route('/jobs/:jobId')
    .get(getJobDetailsForAdmin)
    .put(updateJobByAdmin)
    .delete(deleteJobByAdmin);

router.put('/jobs/:jobId/manage', manageJobPosts); 

router.get('/users/all', getAllUsers);
router.get('/users/role', getAllUsersByRole);
router.get('/users/employer/:empId', getFullEmployerDetails);
router.get('/users/college/:collegeId', getFullCollegeDetails);

router.route('/users/:userId')
    .get(getFullUserDetails)
    .delete(deleteUserByAdmin);
    
router.put('/users/:userId/status', updateUserStatus);
router.put('/users/college/:userId/profile', updateCollegeProfileByAdmin);
router.put('/users/employer/:userId/profile', updateEmployerProfileByAdmin);

router.get('/applications', getWorkflowApplications);
router.get('/applications/all', getAllApplications);
router.get('/applications/pending-approval', getPendingApplications);
router.get('/applications/pending-documents', getPendingDocumentApplications);
router.get('/applications/interviews', getInterviewApplications);
router.put('/applications/:appId', updateApplicationByAdmin);
router.put('/applications/:appId/verify-documents', verifyDocuments);
router.put('/applications/:appId/forward-interview', forwardInterviewToEmployer);
router.put('/applications/:appId/forward-offer', agreementUpload, forwardOfferToEmployer);

router.route('/reviews').get(getAllReviews).post(createReviewByAdmin);
router.route('/reviews/:reviewId').put(updateReview).delete(deleteReview);

router.get('/colleges', getCollegeListForAdmin);


export default router;