
import mongoose from 'mongoose';

const salaryGuideSchema = new mongoose.Schema({
    jobTitle: {
        type: String,
        required: [true, 'Job title is required.'],
        trim: true,
        unique: true
    },
    category: {
        type: String,
        required: [true, 'Category is required.'],
        trim: true
    },
    averageSalary: {
        type: Number,
        required: [true, 'Average salary is required.']
    },
    salaryRange: {
        min: {
            type: Number,
            required: [true, 'Minimum salary is required.']
        },
        max: {
            type: Number,
            required: [true, 'Maximum salary is required.']
        }
    },
    jobDescription: {
        type: String,
        required: [true, 'Job description is required.']
    },
    commonSkills: {
        type: [String],
        default: []
    },
    relatedProfiles: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'SalaryGuide'
    }]
}, {
    timestamps: true
});

export const SalaryGuide = mongoose.model('SalaryGuide', salaryGuideSchema);