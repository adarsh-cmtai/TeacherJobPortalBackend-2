import express from 'express';
import { protect } from '../../middleware/authMiddleware.js';
import { getMyNotifications, markAllAsRead, markOneAsRead } from '../controllers/notification.controller.js';

const router = express.Router();
router.use(protect);

router.get('/', getMyNotifications);
router.put('/read', markAllAsRead);
router.put('/:notifId/read', markOneAsRead);

export default router;