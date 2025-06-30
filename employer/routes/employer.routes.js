import express from 'express';
import { protect, restrictTo } from '../../middleware/authMiddleware.js';
import {
    getMyProfile, updateProfileDetails, updateProfileVisibility, addExperience, updateExperience, deleteExperience,
    addEducation, updateEducation, deleteEducation, updateSkills, uploadProfilePicture, uploadDemoVideo, uploadDocument,
    getMyApplications, applyToJob, saveJob, unsaveJob, updateApplication, withdrawApplication, updateEmployerNotificationSettings,
    submitAcceptance
} from '../controllers/employer.controller.js';
import { upload, documentUploads } from '../../middleware/multer.js';

const router = express.Router();
router.use(protect, restrictTo('employer'));

router.route('/profile').get(getMyProfile).put(updateProfileDetails);
router.put('/profile/visibility', updateProfileVisibility);
router.put('/settings/notifications', updateEmployerNotificationSettings);

router.route('/experience').post(addExperience);
router.route('/experience/:expId').put(updateExperience).delete(deleteExperience);

router.route('/education').post(addEducation);
router.route('/education/:eduId').put(updateEducation).delete(deleteEducation);

router.route('/skills').put(updateSkills);

router.post('/upload/picture', upload.single('profilePicture'), uploadProfilePicture);
router.post('/upload/video', upload.single('demoVideo'), uploadDemoVideo);
router.post('/upload/document', upload.single('document'), uploadDocument);

router.get('/applications', getMyApplications);
router.post('/applications/apply/:jobId', applyToJob);
router.post('/applications/save/:jobId', saveJob);
router.delete('/applications/save/:appId', unsaveJob);
router.post('/applications/:appId/submit-acceptance', documentUploads, submitAcceptance);

router.route('/applications/:appId').put(updateApplication).delete(withdrawApplication);

export default router;