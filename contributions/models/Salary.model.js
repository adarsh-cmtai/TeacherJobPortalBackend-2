import mongoose from 'mongoose';

const salarySchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    schoolName: { type: String, required: true },
    jobTitle: { type: String, required: true },
    yearsOfExperience: { type: Number, required: true },
    salary: { type: Number, required: true },
    salaryType: { type: String, enum: ['per_month', 'per_year'], default: 'per_year' }
}, { timestamps: true });

export const Salary = mongoose.model('Salary', salarySchema);