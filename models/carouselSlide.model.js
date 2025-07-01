import mongoose from 'mongoose';

const carouselSlideSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    subtitle: { type: String, required: true, trim: true },
    description: { type: String, required: true },
    primaryButtonText: { type: String, required: true },
    primaryButtonLink: { type: String, required: true },
    secondaryButtonText: { type: String, required: true },
    secondaryButtonLink: { type: String, required: true },
    backgroundType: { type: String, enum: ['image', 'video'], required: true },
    backgroundMedia: {
        public_id: { type: String, required: true },
        url: { type: String, required: true },
    },
    gradient: { type: String, required: true },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
}, { timestamps: true });

export const CarouselSlide = mongoose.model('CarouselSlide', carouselSlideSchema);
