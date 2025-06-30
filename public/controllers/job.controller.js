import { Job } from '../../models/Job.model.js';

export const getActiveJobs = async (req, res) => {
    try {
        const jobs = await Job.find({ status: 'active' }).sort({ createdAt: -1 });
        res.status(200).json(jobs);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};