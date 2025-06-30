import { Notification } from '../models/notification.model.js';

export const createNotification = async (recipientId, message, link) => {
    try {
        await Notification.create({ recipient: recipientId, message, link });
    } catch (error) {
        console.error("Error creating notification:", error);
    }
};

export const getMyNotifications = async (req, res) => {
    try {
        const notifications = await Notification.find({ recipient: req.user.id }).sort({ createdAt: -1 });
        res.status(200).json(notifications);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const markAllAsRead = async (req, res) => {
    try {
        await Notification.updateMany({ recipient: req.user.id, read: false }, { $set: { read: true } });
        res.status(200).json({ success: true, message: "All notifications marked as read." });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const markOneAsRead = async (req, res) => {
    try {
        const { notifId } = req.params;
        const notification = await Notification.findOneAndUpdate(
            { _id: notifId, recipient: req.user.id },
            { $set: { read: true } },
            { new: true }
        );
        if (!notification) {
            return res.status(404).json({ message: 'Notification not found or permission denied.' });
        }
        res.status(200).json(notification);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};