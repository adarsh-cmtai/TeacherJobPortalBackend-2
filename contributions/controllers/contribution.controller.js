import { Salary } from '../models/Salary.model.js';
import { Interview } from '../models/Interview.model.js';
import { Photo } from '../models/Photo.model.js';
import { uploadOnS3, deleteFromS3 } from '../../config/s3Config.js';

// Salary Controllers
export const getMySalaries = async (req, res) => {
    try {
        const salaries = await Salary.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.status(200).json(salaries);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const addSalary = async (req, res) => {
    try {
        const salary = await Salary.create({ ...req.body, user: req.user.id });
        res.status(201).json(salary);
    } catch (error) { res.status(400).json({ message: error.message }); }
};

export const updateSalary = async (req, res) => {
    try {
        const salary = await Salary.findOneAndUpdate({ _id: req.params.id, user: req.user.id }, req.body, { new: true });
        if (!salary) return res.status(404).json({ message: 'Salary record not found.' });
        res.status(200).json(salary);
    } catch (error) { res.status(400).json({ message: error.message }); }
};

export const deleteSalary = async (req, res) => {
    try {
        const salary = await Salary.findOneAndDelete({ _id: req.params.id, user: req.user.id });
        if (!salary) return res.status(404).json({ message: 'Salary record not found.' });
        res.status(200).json({ success: true, message: 'Salary record deleted.' });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

// Interview Controllers
export const getMyInterviews = async (req, res) => {
    try {
        const interviews = await Interview.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.status(200).json(interviews);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const addInterview = async (req, res) => {
    try {
        const interview = await Interview.create({ ...req.body, user: req.user.id });
        res.status(201).json(interview);
    } catch (error) { res.status(400).json({ message: error.message }); }
};

export const updateInterview = async (req, res) => {
    try {
        const interview = await Interview.findOneAndUpdate({ _id: req.params.id, user: req.user.id }, req.body, { new: true });
        if (!interview) return res.status(404).json({ message: 'Interview record not found.' });
        res.status(200).json(interview);
    } catch (error) { res.status(400).json({ message: error.message }); }
};

export const deleteInterview = async (req, res) => {
    try {
        const interview = await Interview.findOneAndDelete({ _id: req.params.id, user: req.user.id });
        if (!interview) return res.status(404).json({ message: 'Interview record not found.' });
        res.status(200).json({ success: true, message: 'Interview record deleted.' });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

// Photo Controllers
export const getMyPhotos = async (req, res) => {
    try {
        const photos = await Photo.find({ user: req.user.id }).sort({ createdAt: -1 });
        res.status(200).json(photos);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const addPhoto = async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'No image file uploaded.' });
        const result = await uploadOnS3(req.file.buffer, 'school_photos', req.file.mimetype);
        const photo = await Photo.create({
            ...req.body,
            user: req.user.id,
            image: { public_id: result.public_id, url: result.url }
        });
        res.status(201).json(photo);
    } catch (error) { res.status(400).json({ message: error.message }); }
};

export const deletePhoto = async (req, res) => {
    try {
        const photo = await Photo.findOneAndDelete({ _id: req.params.id, user: req.user.id });
        if (!photo) return res.status(404).json({ message: 'Photo not found.' });
        await deleteFromS3(photo.image.public_id);
        res.status(200).json({ success: true, message: 'Photo deleted.' });
    } catch (error) { res.status(500).json({ message: error.message }); }
};