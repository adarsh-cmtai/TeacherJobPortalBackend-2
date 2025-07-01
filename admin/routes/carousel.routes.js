import express from 'express';
import { createSlide, getAllSlides, updateSlide, deleteSlide } from '../controllers/carousel.controller.js';
import { slideMediaUpload } from '../../middleware/multer.js';
import { protect, restrictTo } from '../../middleware/authMiddleware.js';

const router = express.Router();

router.use(protect, restrictTo('Admin'));

router.route('/')
    .get(getAllSlides)
    .post(slideMediaUpload, createSlide);

router.route('/:id')
    .put(slideMediaUpload, updateSlide)
    .delete(deleteSlide);

export default router;
