import mongoose from 'mongoose';
const adminProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    jobTitle: { type: String, default: 'Administrator' },
    phone: { type: String },
    avatar: {
        public_id: String,
        url: String
    },
    permissions: [String]
}, { timestamps: true });
export const AdminProfile = mongoose.model('AdminProfile', adminProfileSchema);