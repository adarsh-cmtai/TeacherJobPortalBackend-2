import asyncHandler from 'express-async-handler';
import PostJob from '../models/postJob.model.js';
// Correct the path to your User model if necessary
import { User } from '../../models/User.model.js'; 

// ... (getMyJobs function remains the same) ...
export const getMyJobs = asyncHandler(async (req, res) => {
  const jobs = await PostJob.find({ postedBy: req.user.id }).sort({ createdAt: -1 });
  res.status(200).json(jobs);
});


export const createJobByEmployer = asyncHandler(async (req, res) => {
  const { 
    title, location, jobType, category, description, 
    experienceLevel, yearsOfExperience, requiredSkills 
  } = req.body;

  if (!title || !location || !jobType || !category || !description || !experienceLevel || !yearsOfExperience || !requiredSkills) {
    res.status(400);
    throw new Error('Please provide all required job details.');
  }

  // --- THIS IS THE CORRECTED LOGIC ---
  const user = await User.findById(req.user.id).populate('employerProfile', 'name');
  
  if (!user || !user.employerProfile) {
    res.status(404);
    throw new Error('Employer profile not found.');
  }
  // --- END OF CORRECTION ---

  const job = await PostJob.create({
    title,
    location,
    jobType,
    category,
    description,
    experienceLevel,
    yearsOfExperience,
    requiredSkills,
    schoolName: user.employerProfile.name, // Get name from the populated profile
    postedBy: req.user.id,
    status: 'pending',
  });

  res.status(201).json(job);
});


// ... (updateJobByEmployer and deleteJobByEmployer functions remain the same) ...
export const updateJobByEmployer = asyncHandler(async (req, res) => {
  const job = await PostJob.findById(req.params.id);

  if (!job) {
    res.status(404);
    throw new Error('Job not found.');
  }

  if (job.postedBy.toString() !== req.user.id) {
    res.status(401);
    throw new Error('User not authorized to update this job.');
  }

  const updateData = { ...req.body, status: 'pending' };

  const updatedJob = await PostJob.findByIdAndUpdate(req.params.id, updateData, {
    new: true,
    runValidators: true,
  });

  res.status(200).json(updatedJob);
});

export const deleteJobByEmployer = asyncHandler(async (req, res) => {
  const job = await PostJob.findById(req.params.id);

  if (!job) {
    res.status(404);
    throw new Error('Job not found.');
  }

  if (job.postedBy.toString() !== req.user.id) {
    res.status(401);
    throw new Error('User not authorized to delete this entry.');
  }

  await PostJob.findByIdAndDelete(req.params.id);
  
  res.status(200).json({ id: req.params.id, message: 'Job deleted successfully.' });
});