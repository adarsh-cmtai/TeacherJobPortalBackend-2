import { Job } from '../../models/Job.model.js';
import { Application } from '../../employer/models/application.model.js';
import { User } from '../../models/User.model.js';
import { EmployerProfile } from '../../employer/models/profile.model.js';
import { CollegeProfile } from '../../college/models/profile.model.js';
import { AdminProfile } from '../models/profile.model.js';
import { Review } from '../../models/Review.model.js';
import { createNotification } from '../../notifications/controllers/notification.controller.js';
import mongoose from 'mongoose';
import { uploadOnS3 } from '../../config/s3Config.js';

export const getCollegeListForAdmin = async (req, res) => {
    try {
        const colleges = await CollegeProfile.find({}).select('_id name user');
        res.status(200).json(colleges);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getPublicColleges = async (req, res) => {
    try {
        const colleges = await CollegeProfile.aggregate([
            { $match: { name: { $exists: true, $ne: '' } } },
            { $lookup: { from: 'reviews', localField: '_id', foreignField: 'college', as: 'reviews' } },
            { $addFields: { reviewCount: { $size: '$reviews' }, averageRating: { $avg: '$reviews.rating' } } },
            { $project: { reviews: 0 } }
        ]);
        res.status(200).json(colleges);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllColleges = async (req, res) => {
    try {
        const colleges = await CollegeProfile.find({}).select('name logo website');
        res.status(200).json(colleges);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getDashboardStats = async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalJobs = await Job.countDocuments();
        const pendingJobs = await Job.countDocuments({ status: 'pending_approval' });
        const totalApplications = await Application.countDocuments();
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const newUsersLast7Days = await User.countDocuments({ createdAt: { $gte: sevenDaysAgo } });
        res.status(200).json({
            totalUsers,
            totalJobs,
            pendingJobs,
            totalApplications,
            newUsersLast7Days
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getMyAdminProfile = async (req, res) => {
    try {
        let profile = await AdminProfile.findOne({ user: req.user.id }).populate('user', 'email role');
        if (!profile) {
            profile = await AdminProfile.create({
                user: req.user.id,
                name: req.user.email.split('@')[0],
                jobTitle: 'Administrator'
            });
            profile = await AdminProfile.findById(profile._id).populate('user', 'email role');
        }
        res.status(200).json(profile);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateMyAdminProfile = async (req, res) => {
    try {
        const profile = await AdminProfile.findOneAndUpdate({ user: req.user.id }, { $set: req.body }, { new: true, runValidators: true });
        if (!profile) {
            return res.status(404).json({ message: "Profile not found" });
        }
        res.status(200).json(profile);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getWorkflowApplications = async (req, res) => {
    try {
        const applications = await Application.find({
            status: { $in: ['interview_scheduled', 'offer_extended', 'hired', 'rejected'] }
        })
        .populate({
            path: 'user',
            select: 'email',
            populate: { path: 'employerProfile', model: 'EmployerProfile', select: 'name' }
        })
        .populate({
            path: 'job',
            select: 'title schoolName',
        })
        .sort({ updatedAt: -1 });
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateApplicationByAdmin = async (req, res) => {
    try {
        const { appId } = req.params;
        const { status } = req.body;
        const application = await Application.findById(appId);
        if (!application) {
            return res.status(404).json({ message: 'Application not found.' });
        }
        const previousStatus = application.status;
        application.set(req.body);
        await application.save();
        const job = await Job.findById(application.job);
        if (previousStatus === 'pending_admin_approval' && status === 'applied') {
            const message = `A new application for your job posting '${job.title}' has been approved and is ready for review.`;
            await createNotification(job.postedBy, message, '/college/applications');
        }
        if (status === 'rejected') {
            const message = `An application for '${job.title}' was reviewed by the admin and did not proceed.`;
            await createNotification(job.postedBy, message, '/college/applications');
        }
        res.status(200).json(application);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllApplications = async (req, res) => {
    try {
        const applications = await Application.find({})
            .populate({
                path: 'user',
                select: 'email',
                populate: { path: 'employerProfile', model: 'EmployerProfile', select: 'name' }
            })
            .populate({
                path: 'job',
                select: 'title schoolName',
                populate: { path: 'postedBy', select: 'collegeProfile', populate: { path: 'collegeProfile', model: 'CollegeProfile', select: 'name' } }
            })
            .sort({ updatedAt: -1 });
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getPendingApplications = async (req, res) => {
    try {
        const applications = await Application.find({ status: 'pending_admin_approval' })
            .populate({
                path: 'user',
                populate: {
                    path: 'employerProfile',
                    populate: { path: 'skills', model: 'Skill' }
                }
            })
            .populate('job')
            .sort({ createdAt: 'desc' });
        res.status(200).json(applications);
    } catch (error) {
        console.error("Error in getPendingApplications:", error);
        res.status(500).json({ message: error.message });
    }
};

export const createJobByAdmin = async (req, res) => {
    try {
        const { title, schoolName, location, description, type, salary, postedBy } = req.body;
        if (!title || !schoolName || !location || !postedBy) {
            return res.status(400).json({ message: 'Title, schoolName, location, and postedBy (college user ID) are required.' });
        }
        const job = await Job.create({
            title, schoolName, location, description, type, salary,
            postedBy,
            approvedBy: req.user.id,
            status: 'active'
        });
        res.status(201).json(job);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateJobByAdmin = async (req, res) => {
    try {
        const { jobId } = req.params;
        const job = await Job.findByIdAndUpdate(jobId, req.body, { new: true, runValidators: true });
        if (!job) {
            return res.status(404).json({ message: 'Job not found.' });
        }
        res.status(200).json(job);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const deleteJobByAdmin = async (req, res) => {
    try {
        const { jobId } = req.params;
        const job = await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ message: 'Job not found.' });
        }
        await Application.deleteMany({ job: jobId });
        await Job.findByIdAndDelete(jobId);
        res.status(200).json({ success: true, message: 'Job and all associated applications have been deleted.' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const manageJobPosts = async (req, res) => {
    try {
        const { jobId } = req.params;
        const { status } = req.body;
        const job = await Job.findByIdAndUpdate(jobId, { status, approvedBy: req.user.id }, { new: true });
        
        if (job) {
            const message = `Your job post '${job.title}' has been ${status}.`;
            await createNotification(job.postedBy, message, '/college/jobs');
        }

        res.status(200).json(job);
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const getAllJobs = async (req, res) => {
    try {
        const jobs = await Job.aggregate([
            { $match: {} },
            { $lookup: { from: 'applications', localField: '_id', foreignField: 'job', as: 'applications' } },
            { $addFields: { applicantCount: { $size: '$applications' } } },
            { $lookup: { from: 'users', localField: 'postedBy', foreignField: '_id', as: 'postedByUser' } },
            { $unwind: { path: '$postedByUser', preserveNullAndEmptyArrays: true } },
            { $project: { applications: 0, 'postedByUser.password': 0, } },
            { $sort: { createdAt: -1 } }
        ]);
        res.status(200).json(jobs);
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const getPendingJobs = async (req, res) => {
    try {
        const jobs = await Job.find({ status: 'pending_approval' }).populate({
            path: 'postedBy',
            select: 'email',
            populate: {
                path: 'collegeProfile',
                model: 'CollegeProfile',
                select: 'name'
            }
        }).sort({ createdAt: -1 });
        res.status(200).json(jobs);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getJobDetailsForAdmin = async (req, res) => {
    try {
        const { jobId } = req.params;
        const job = await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ message: 'Job not found.' });
        }
        res.status(200).json(job);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllUsersByRole = async (req, res) => {
    try {
        const { role } = req.query;
        if (!role) {
            return res.status(400).json({ message: 'Role query parameter is required' });
        }
        
        const users = await User.find({ role }).select('-password');
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({})
            .populate('employerProfile', 'name')
            .populate('collegeProfile', 'name')
            .populate('adminProfile', 'name')
            .select('-password');
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getFullUserDetails = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId).select('-password');
        if (!user) return res.status(404).json({ message: "User not found." });

        let details = { user };

        if (user.role === 'employer') {
            details.profile = await EmployerProfile.findOne({ user: userId }).populate('skills', 'name');
            details.applications = await Application.find({ user: userId }).populate('job', 'title schoolName');
        } else if (user.role === 'college') {
            details.profile = await CollegeProfile.findOne({ user: userId });
            details.jobs = await Job.find({ postedBy: userId });
        } else if (user.role === 'admin') {
            details.profile = await AdminProfile.findOne({ user: userId });
        }
        
        res.status(200).json(details);
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const updateUserStatus = async (req, res) => {
    try {
        const { userId } = req.params;
        const { status } = req.body;
        if (!['active', 'pending', 'suspended'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status.' });
        }
        const user = await User.findByIdAndUpdate(userId, { status }, { new: true });
        if (!user) return res.status(404).json({ message: 'User not found.' });
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateCollegeProfileByAdmin = async (req, res) => {
    try {
        const { userId } = req.params;
        const profile = await CollegeProfile.findOneAndUpdate({ user: userId }, req.body, { new: true, runValidators: true });
        if (!profile) return res.status(404).json({ message: 'College profile not found.' });
        res.status(200).json(profile);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateEmployerProfileByAdmin = async (req, res) => {
    try {
        const { userId } = req.params;
        const profile = await EmployerProfile.findOneAndUpdate({ user: userId }, req.body, { new: true, runValidators: true });
        if (!profile) return res.status(404).json({ message: 'Employer profile not found.' });
        res.status(200).json(profile);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const deleteUserByAdmin = async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        if (user._id.equals(req.user.id)) {
            return res.status(403).json({ message: "Admin cannot delete their own account." });
        }
        if (user.role === 'employer') {
            await EmployerProfile.deleteOne({ user: userId });
            await Application.deleteMany({ user: userId });
        } else if (user.role === 'college') {
            const jobs = await Job.find({ postedBy: userId }).select('_id');
            const jobIds = jobs.map(job => job._id);
            if (jobIds.length > 0) {
                await Application.deleteMany({ job: { $in: jobIds } });
            }
            await Job.deleteMany({ postedBy: userId });
            await CollegeProfile.deleteOne({ user: userId });
        } else if (user.role === 'admin') {
            await AdminProfile.deleteOne({ user: userId });
        }
        await User.findByIdAndDelete(userId);
        res.status(200).json({ success: true, message: `User with role ${user.role} and all associated data has been deleted.` });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getFullEmployerDetails = async (req, res) => {
    try {
        const { empId } = req.params;
        const employer = await User.findById(empId).select('-password');
        if (!employer) return res.status(404).json({ message: "Employer not found." });
        const profile = await EmployerProfile.findOne({ user: empId });
        const applications = await Application.find({ user: empId }).populate('job', 'title schoolName status');
        res.status(200).json({ employer, profile, applications });
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const getFullCollegeDetails = async (req, res) => {
    try {
        const { collegeId } = req.params;
        const college = await User.findById(collegeId).select('-password');
        if (!college) return res.status(404).json({ message: "College not found." });
        const profile = await CollegeProfile.findOne({ user: collegeId });
        const jobs = await Job.find({ postedBy: collegeId });
        const jobIds = jobs.map(j => j._id);
        const hiredCount = await Application.countDocuments({ job: { $in: jobIds }, status: 'hired' });
        res.status(200).json({ college, profile, jobs, hiredCount });
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const forwardInterviewToEmployer = async (req, res) => {
    try {
        const { appId } = req.params;
        const application = await Application.findByIdAndUpdate(
            appId, 
            { 'interviewDetails.confirmedByAdmin': true }, 
            { new: true }
        ).populate('job user');
        
        if (application) {
            const message = `An interview has been scheduled for the ${application.job.title} position. Please check your applications for details.`;
            await createNotification(application.user._id, message, '/my-jobs?category=interviews');
        }
        
        res.status(200).json({ success: true, message: "Interview details forwarded to employer." });
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const forwardOfferToEmployer = async (req, res) => {
    try {
        const { appId } = req.params;
        if (!req.file) {
            return res.status(400).json({ message: 'Agreement PDF is required.' });
        }

        const agreementResult = await uploadOnS3(req.file.buffer, 'agreements', req.file.mimetype);
        
        const application = await Application.findByIdAndUpdate(
            appId, 
            { 
                'offerLetter.forwardedByAdmin': true,
                agreementLetter: {
                    public_id: agreementResult.public_id,
                    url: agreementResult.url
                }
            }, 
            { new: true }
        ).populate('job user');
        
        if (application) {
            const message = `Congratulations! You have received an offer for the ${application.job.title} position.`;
            await createNotification(application.user._id, message, '/my-jobs?category=offers');
        }
        
        res.status(200).json({ success: true, message: "Offer letter and agreement forwarded to employer." });
    } catch (error) { 
        res.status(500).json({ message: error.message }); 
    }
};

export const getPendingDocumentApplications = async (req, res) => {
    try {
        const applications = await Application.find({ status: 'pending_document_approval' })
            .populate({
                path: 'user',
                select: 'email',
                populate: { path: 'employerProfile', model: 'EmployerProfile', select: 'name' }
            })
            .populate('job', 'title schoolName')
            .sort({ updatedAt: -1 });
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const verifyDocuments = async (req, res) => {
    try {
        const { appId } = req.params;
        const { status } = req.body; 

        if (!['documents_approved', 'documents_rejected'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status for document verification.' });
        }

        const application = await Application.findById(appId).populate('job');

        if (!application) {
            return res.status(404).json({ message: 'Application not found.' });
        }

        application.status = status;
        await application.save();
        
        if (status === 'documents_approved') {
            const message = `Documents for your application to '${application.job.title}' have been approved and forwarded to the college.`;
            await createNotification(application.job.postedBy, message, '/college/applications/offers');
        } else {
            const message = `There was an issue with the documents for your application to '${application.job.title}'. Please review and contact support.`;
            await createNotification(application.user, message, '/my-jobs');
        }
        
        res.status(200).json({ success: true, data: application });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getInterviewApplications = async (req, res) => {
    try {
        const applications = await Application.find({ status: { $in: ['interview_scheduled', 'offer_extended', 'hired'] } })
            .populate({
                path: 'user',
                select: 'email',
                populate: { path: 'employerProfile', model: 'EmployerProfile', select: 'name' }
            })
            .populate('job', 'title schoolName')
            .sort({ 'interviewDetails.scheduledOn': -1 });
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};