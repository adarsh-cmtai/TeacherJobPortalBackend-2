import { Review } from '../../models/Review.model.js';
import { CollegeProfile } from '../../college/models/profile.model.js';

export const createReviewByAdmin = async (req, res) => {
    try {
        const { collegeId, title, content, rating } = req.body;
        
        // Use the admin's own user ID for the review
        const review = await Review.create({
            user: req.user.id, 
            college: collegeId,
            title,
            content,
            rating,
            status: 'approved' // Admin reviews are auto-approved
        });
        res.status(201).json(review);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllReviews = async (req, res) => {
    try {
        const reviews = await Review.find({})
            .populate({
                path: 'user',
                select: 'email',
                populate: { path: 'employerProfile', select: 'name' }
            })
            .populate({
                path: 'college',
                select: 'name'
            })
            .sort({ createdAt: -1 });
        res.status(200).json(reviews);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateReview = async (req, res) => {
    try {
        const { reviewId } = req.params;
        const review = await Review.findByIdAndUpdate(reviewId, req.body, { new: true, runValidators: true });
        if (!review) {
            return res.status(404).json({ message: 'Review not found.' });
        }
        res.status(200).json(review);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const deleteReview = async (req, res) => {
    try {
        const { reviewId } = req.params;
        const review = await Review.findByIdAndDelete(reviewId);
        if (!review) {
            return res.status(404).json({ message: 'Review not found.' });
        }
        res.status(200).json({ success: true, message: 'Review deleted successfully.' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};