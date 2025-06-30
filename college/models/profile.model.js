import mongoose from 'mongoose';
const collegeProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    name: { type: String, required: true },
    address: String,
    website: String,
    description: String,
    logo: { public_id: String, url: String },
    phone: { type: String, default: '' },
    established: { type: String, default: '' },
    accreditation: { type: String, default: 'NOT_ACCREDITED' },
    studentCount: { type: String, default: '0' },
    facultyCount: { type: String, default: '0' },
    departments: { type: [String], default: [] },
    facilities: { type: [String], default: [] },
    settings: {
        notifications: {
            newApplications: { type: Boolean, default: true },
            jobStatusUpdates: { type: Boolean, default: true },
        },
        privacy: {
            displayContactInfo: { type: Boolean, default: true },
            shareStudentData: { type: Boolean, default: false },
        }
    }
}, { timestamps: true });
export const CollegeProfile = mongoose.model('CollegeProfile', collegeProfileSchema);