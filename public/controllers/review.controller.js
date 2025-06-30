import { Review } from '../../models/Review.model.js';
import { CollegeProfile } from '../../college/models/profile.model.js';
import mongoose from 'mongoose';

export const getReviewsByCollege = async (req, res) => {
    try {
        const { collegeId } = req.params;

        const college = await CollegeProfile.findById(collegeId).select('name logo');
        if (!college) {
            return res.status(404).json({ message: 'College not found.' });
        }

        const reviews = await Review.find({ college: collegeId, status: 'approved' })
            .populate({
                path: 'user',
                select: 'employerProfile',
                populate: {
                    path: 'employerProfile',
                    select: 'name'
                }
            })
            .sort({ createdAt: -1 });

        const stats = await Review.aggregate([
            { $match: { college: new mongoose.Types.ObjectId(collegeId), status: 'approved' } },
            { $group: {
                _id: '$college',
                averageRating: { $avg: '$rating' },
                reviewCount: { $sum: 1 }
            }}
        ]);

        res.status(200).json({
            college,
            reviews,
            stats: stats[0] || { averageRating: 0, reviewCount: 0 }
        });

    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};