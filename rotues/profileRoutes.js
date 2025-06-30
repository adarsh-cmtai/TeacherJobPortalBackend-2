import express from 'express';
import { protect } from '../middleware/authMiddleware.js';
import { upload } from '../middleware/multer.js';
import { 
    getMyProfile,
    updateProfile,
    addExperience,
    updateExperience,
    deleteExperience,
    addEducation,
    updateEducation,
    deleteEducation,
    updateSkills,
    uploadProfilePicture,
    uploadDemoVideo,
    uploadDocument
} from '../controllers/profileController.js';

const router = express.Router();

router.use(protect);

router.route('/')
    .get(getMyProfile)
    .put(updateProfile);

router.route('/experience')
    .post(addExperience);

router.route('/experience/:id')
    .put(updateExperience)
    .delete(deleteExperience);

router.route('/education')
    .post(addEducation);

router.route('/education/:id')
    .put(updateEducation)
    .delete(deleteEducation);

router.route('/skills')
    .put(updateSkills);

router.post('/upload/picture', upload.single('profilePicture'), uploadProfilePicture);
router.post('/upload/video', upload.single('demoVideo'), uploadDemoVideo);
router.post('/upload/document', upload.single('document'), uploadDocument);

export default router;