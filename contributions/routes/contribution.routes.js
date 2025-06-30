import express from 'express';
import { protect, restrictTo } from '../../middleware/authMiddleware.js';
import { upload } from '../../middleware/multer.js';
import {
    getMySalaries, addSalary, updateSalary, deleteSalary,
    getMyInterviews, addInterview, updateInterview, deleteInterview,
    getMyPhotos, addPhoto, deletePhoto
} from '../controllers/contribution.controller.js';

const router = express.Router();

router.use(protect, restrictTo('employer'));

// Salary Routes
router.route('/salaries').get(getMySalaries).post(addSalary);
router.route('/salaries/:id').put(updateSalary).delete(deleteSalary);

// Interview Routes
router.route('/interviews').get(getMyInterviews).post(addInterview);
router.route('/interviews/:id').put(updateInterview).delete(deleteInterview);

// Photo Routes
router.route('/photos').get(getMyPhotos).post(upload.single('image'), addPhoto);
router.route('/photos/:id').delete(deletePhoto);

export default router;