import mongoose from 'mongoose';

const interviewSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    schoolName: { type: String, required: true },
    jobTitle: { type: String, required: true },
    question: { type: String, required: true },
    answer: { type: String }
}, { timestamps: true });

export const Interview = mongoose.model('Interview', interviewSchema);