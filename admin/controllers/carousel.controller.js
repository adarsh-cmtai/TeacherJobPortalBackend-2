import { CarouselSlide } from '../../models/carouselSlide.model.js';
import { uploadOnS3, deleteFromS3 } from '../../config/s3Config.js';

export const createSlide = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: "A background image or video is required." });
        }

        const mediaUploadResult = await uploadOnS3(req.file.buffer, "carousel-slides", req.file.mimetype);

        const newSlide = await CarouselSlide.create({
            ...req.body,
            backgroundMedia: mediaUploadResult,
        });
        res.status(201).json({ success: true, data: newSlide });
    } catch (error) {
        res.status(400).json({ success: false, message: error.message });
    }
};

export const getAllSlides = async (req, res) => {
    try {
        const slides = await CarouselSlide.find({}).sort({ createdAt: -1 });
        res.status(200).json({ success: true, data: slides });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

export const updateSlide = async (req, res) => {
    try {
        const existingSlide = await CarouselSlide.findById(req.params.id);
        if (!existingSlide) {
            return res.status(404).json({ success: false, message: "Slide not found." });
        }

        const updatedData = { ...req.body };
        if (req.file) {
            await deleteFromS3(existingSlide.backgroundMedia.public_id);
            const mediaUploadResult = await uploadOnS3(req.file.buffer, "carousel-slides", req.file.mimetype);
            updatedData.backgroundMedia = mediaUploadResult;
        }

        const slide = await CarouselSlide.findByIdAndUpdate(req.params.id, updatedData, { new: true });
        res.status(200).json({ success: true, data: slide });
    } catch (error) {
        res.status(400).json({ success: false, message: error.message });
    }
};

export const deleteSlide = async (req, res) => {
    try {
        const slide = await CarouselSlide.findById(req.params.id);
        if (!slide) {
            return res.status(404).json({ success: false, message: "Slide not found." });
        }

        await deleteFromS3(slide.backgroundMedia.public_id);
        await CarouselSlide.findByIdAndDelete(req.params.id);

        res.status(200).json({ success: true, message: "Slide deleted successfully." });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

export const getPublishedSlides = async (req, res) => {
    try {
        const slides = await CarouselSlide.find({ status: 'published' });
        res.status(200).json({ success: true, data: slides });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};
