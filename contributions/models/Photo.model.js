import mongoose from 'mongoose';

const photoSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    schoolName: { type: String, required: true },
    caption: { type: String },
    image: {
        public_id: { type: String, required: true },
        url: { type: String, required: true }
    }
}, { timestamps: true });

export const Photo = mongoose.model('Photo', photoSchema);