import mongoose from 'mongoose';

const acceptanceDocumentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    documentType: { type: String, enum: ['aadhar', 'pan', 'result', 'experience', 'signedAgreement'], required: true },
    public_id: { type: String, required: true },
    url: { type: String, required: true },
});

const applicationSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    job: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
    status: {
        type: String,
        enum: ['saved', 'pending_admin_approval', 'applied', 'viewed', 'shortlisted', 'interview_scheduled', 'offer_extended', 'pending_document_approval', 'documents_approved', 'hired', 'rejected'],
        default: 'pending_admin_approval'
    },
    category: {
        type: String,
        enum: ['saved', 'applied', 'interviews', 'offers', 'hired', 'archived'],
        required: true
    },
    appliedDate: { type: Date, default: Date.now },
    interviewDetails: {
        scheduledOn: { type: Date },
        interviewType: { type: String, enum: ['Online', 'In-Person', 'Telephonic'] },
        notes: { type: String },
        meetingLink: { type: String },
        confirmedByAdmin: { type: Boolean, default: false }
    },
    offerDetails: {
        offerText: { type: String },
        joiningDate: { type: Date },
        salary: { type: String }
    },
    offerLetter: {
        public_id: String,
        url: String,
        forwardedByAdmin: { type: Boolean, default: false }
    },
    agreementLetter: {
        public_id: String,
        url: String
    },
    termsAndConditionsAccepted: {
        type: Boolean,
        default: false
    },
    acceptanceDocuments: [acceptanceDocumentSchema]
}, { timestamps: true });

applicationSchema.index({ user: 1, job: 1 }, { unique: true });

export const Application = mongoose.model('Application', applicationSchema);