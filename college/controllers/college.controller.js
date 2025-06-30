import { Job } from '../../models/Job.model.js';
import { Application } from '../../employer/models/application.model.js';
import { CollegeProfile } from '../models/profile.model.js';
import { uploadOnS3, deleteFromS3 } from '../../config/s3Config.js';
import mongoose from 'mongoose';
import { createNotification } from '../../notifications/controllers/notification.controller.js';

export const getMyCollegeProfile = async (req, res) => {
    try {
        const profile = await CollegeProfile.findOne({ user: req.user.id });
        if (!profile) { return res.status(404).json({ message: 'College profile not found.' }); }
        res.status(200).json(profile);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateMyCollegeProfile = async (req, res) => {
    try {
        const profile = await CollegeProfile.findOneAndUpdate({ user: req.user.id }, { $set: req.body }, { new: true, runValidators: true });
        if (!profile) { return res.status(404).json({ message: "Profile not found" }); }
        res.status(200).json(profile);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateMyCollegeSettings = async (req, res) => {
    try {
        const { notifications, privacy } = req.body;
        const profile = await CollegeProfile.findOneAndUpdate(
            { user: req.user.id },
            { $set: { "settings.notifications": notifications, "settings.privacy": privacy } },
            { new: true, runValidators: true }
        );
        if (!profile) { return res.status(404).json({ message: "Profile not found" }); }
        res.status(200).json(profile.settings);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const createJobPost = async (req, res) => {
    try {
        const collegeProfile = await CollegeProfile.findOne({ user: req.user.id });
        const job = await Job.create({ ...req.body, postedBy: req.user.id, schoolName: collegeProfile.name });
        res.status(201).json(job);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const getMyPostedJobs = async (req, res) => {
    try {
        const jobs = await Job.aggregate([
            { $match: { postedBy: new mongoose.Types.ObjectId(req.user.id) } },
            { $lookup: { from: 'applications', localField: '_id', foreignField: 'job', as: 'applications' } },
            { $addFields: { applicants: { $size: '$applications' } } },
            { $project: { applications: 0 } },
            { $sort: { createdAt: -1 } }
        ]);
        res.status(200).json(jobs);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const getJobByIdForCollege = async (req, res) => {
    try {
        const { jobId } = req.params;
        const job = await Job.findOne({ _id: jobId, postedBy: req.user.id });
        if (!job) { return res.status(404).json({ message: 'Job not found or you do not have permission to view it.' }); }
        res.status(200).json(job);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateMyJob = async (req, res) => {
    try {
        const { jobId } = req.params;
        const job = await Job.findOneAndUpdate({ _id: jobId, postedBy: req.user.id }, { $set: req.body }, { new: true, runValidators: true });
        if (!job) { return res.status(404).json({ message: 'Job not found or you do not have permission to update it.' }); }
        res.status(200).json(job);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const deleteMyJob = async (req, res) => {
    try {
        const { jobId } = req.params;
        const job = await Job.findOne({ _id: jobId, postedBy: req.user.id });
        if (!job) { return res.status(404).json({ message: 'Job not found or you do not have permission to delete it.' }); }
        await Application.deleteMany({ job: jobId });
        await Job.findByIdAndDelete(jobId);
        res.status(200).json({ success: true, message: 'Job and all associated applications have been deleted.' });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const getApplicationsForMyJobs = async (req, res) => {
    try {
        const jobsPostedByCollege = await Job.find({ postedBy: req.user.id }).select('_id');
        const jobIds = jobsPostedByCollege.map(job => job._id);
        const applications = await Application.find({ 
            job: { $in: jobIds },
            status: { $ne: 'hired' } 
        }).populate({
            path: 'user',
            select: 'email',
            populate: {
                path: 'employerProfile',
                select: 'name headline workExperience education documents skills',
                populate: { path: 'skills', select: 'name' }
            }
        }).populate('job', 'title');
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getOfferStageApplications = async (req, res) => {
    try {
        const jobsPostedByCollege = await Job.find({ postedBy: req.user.id }).select('_id');
        const jobIds = jobsPostedByCollege.map(job => job._id);
        const applications = await Application.find({ 
            job: { $in: jobIds },
            status: { $in: ['interview_scheduled', 'offer_extended', 'hired', 'rejected', 'documents_approved'] } 
        }).populate({
            path: 'user',
            select: 'email',
            populate: {
                path: 'employerProfile',
                select: 'name'
            }
        }).populate('job', 'title').sort({ updatedAt: -1 });
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getShortlistedApplications = async (req, res) => {
    try {
        const jobsPostedByCollege = await Job.find({ postedBy: req.user.id }).select('_id');
        const jobIds = jobsPostedByCollege.map(job => job._id);
        const applications = await Application.find({ 
            job: { $in: jobIds },
            status: { $in: ['shortlisted', 'interview_scheduled', 'offer_extended', 'hired', 'documents_approved'] } 
        }).populate({
            path: 'user',
            select: 'email',
            populate: {
                path: 'employerProfile',
                select: 'name phone workExperience education skills'
            }
        }).populate('job', 'title').sort({ updatedAt: -1 });
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateApplicationStatusByCollege = async (req, res) => {
    try {
        const { appId } = req.params;
        const { status } = req.body;
        if (!status) { return res.status(400).json({ message: 'Status is required.' }); }
        const jobsPostedByCollege = await Job.find({ postedBy: req.user.id }).select('_id');
        const jobIds = jobsPostedByCollege.map(job => job._id);
        const application = await Application.findOneAndUpdate(
            { _id: appId, job: { $in: jobIds } },
            { $set: { status: status } },
            { new: true }
        );
        if (!application) { return res.status(404).json({ message: 'Application not found or you do not have permission to update it.' }); }
        res.status(200).json(application);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const scheduleInterview = async (req, res) => {
    try {
        const { appId } = req.params;
        const { scheduledOn, interviewType, notes, meetingLink } = req.body;
        const application = await Application.findByIdAndUpdate(appId, {
            status: 'interview_scheduled',
            category: 'interviews',
            interviewDetails: {
                scheduledOn,
                interviewType,
                notes,
                meetingLink,
                confirmedByAdmin: false
            }
        }, { new: true });
        res.status(200).json(application);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateStatusAfterInterview = async (req, res) => {
    try {
        const { appId } = req.params;
        if (!req.file) {
            return res.status(400).json({ message: 'Offer letter file is required.' });
        }
        const applicationToUpdate = await Application.findById(appId);
        if (!applicationToUpdate) {
            return res.status(404).json({ message: 'Application not found.' });
        }
        const job = await Job.findOne({ _id: applicationToUpdate.job, postedBy: req.user.id });
        if (!job) {
            return res.status(403).json({ message: 'Permission denied. You do not own the job for this application.' });
        }
        const result = await uploadOnS3(req.file.buffer, 'offer_letters', req.file.mimetype);
        const updateData = {
            status: 'offer_extended',
            category: 'offers',
            offerLetter: {
                public_id: result.public_id,
                url: result.url,
                forwardedByAdmin: false
            }
        };
        const updatedApplication = await Application.findByIdAndUpdate(
            appId,
            { $set: updateData },
            { new: true, runValidators: true }
        );
        res.status(200).json(updatedApplication);
    } catch (error) {
        res.status(500).json({ message: 'Server error while updating application.', error: error.message });
    }
};

export const finalizeHiring = async (req, res) => {
    try {
        const { appId } = req.params;
        const { status } = req.body;

        if (!['hired', 'rejected'].includes(status)) {
            return res.status(400).json({ message: 'Invalid final status.' });
        }

        const jobsPostedByCollege = await Job.find({ postedBy: req.user.id }).select('_id');
        const jobIds = jobsPostedByCollege.map(job => job._id);
        const application = await Application.findOne({ _id: appId, job: { $in: jobIds } }).populate('job', 'title');

        if (!application) {
            return res.status(404).json({ message: 'Application not found or permission denied.' });
        }
        
        if (application.status !== 'documents_approved') {
            return res.status(400).json({ message: 'Cannot finalize hiring until documents are approved by admin.' });
        }
        
        application.status = status;
        application.category = status === 'hired' ? 'hired' : 'archived';
        await application.save();

        let message = '';
        if (status === 'hired') {
            message = `Congratulations! The college has confirmed your hiring for the ${application.job.title} position. Welcome aboard!`;
        } else {
            message = `Regarding your application for ${application.job.title}, the college has decided not to proceed at this time. We wish you the best in your job search.`;
        }
        await createNotification(application.user, message, '/my-jobs');

        res.status(200).json({ success: true, data: application });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};