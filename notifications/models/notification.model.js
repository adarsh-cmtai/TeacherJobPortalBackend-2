
import mongoose from 'mongoose';
const notificationSchema = new mongoose.Schema({
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    link: String,
    read: { type: Boolean, default: false }
}, { timestamps: true });
export const Notification = mongoose.model('Notification', notificationSchema);