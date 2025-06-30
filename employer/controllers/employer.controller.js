import { EmployerProfile } from '../models/profile.model.js';
import { Application } from '../models/application.model.js';
import { Skill } from '../../models/Skill.model.js';
import { uploadOnS3, deleteFromS3 } from '../../config/s3Config.js';

const calculateProfileStrength = (profile) => {
    let strength = 0;
    if (profile.name) strength += 10;
    if (profile.headline) strength += 10;
    if (profile.phone) strength += 5;
    if (profile.location) strength += 5;
    if (profile.profilePicture?.url) strength += 15;
    if (profile.demoVideo?.url) strength += 15;
    if (profile.workExperience?.length > 0) strength += 15;
    if (profile.education?.length > 0) strength += 10;
    if (profile.skills?.length > 0) strength += 10;
    return Math.min(strength, 100);
};

export const getMyProfile = async (req, res) => {
    try {
        const profile = await EmployerProfile.findOne({ user: req.user.id }).populate('skills');
        if (!profile) return res.status(404).json({ message: 'Profile not found.' });
        const profileStrength = calculateProfileStrength(profile);
        const maskedEmail = req.user.email.replace(/(.{1})(.*)(@.*)/, "$1********$3");
        res.json({ ...profile.toObject(), profileStrength, email: maskedEmail });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateProfileDetails = async (req, res) => {
    const { name, headline, location, phone } = req.body;
    try {
        const profile = await EmployerProfile.findOneAndUpdate(
            { user: req.user.id },
            { $set: { name, headline, location, phone } },
            { new: true, runValidators: true }
        );
        res.json(profile);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateProfileVisibility = async (req, res) => {
    const { isVisible } = req.body;
    try {
        const profile = await EmployerProfile.findOneAndUpdate(
            { user: req.user.id },
            { $set: { isVisible } },
            { new: true }
        );
        if (!profile) return res.status(404).json({ message: "Profile not found" });
        res.status(200).json(profile);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateEmployerNotificationSettings = async (req, res) => {
    const { emailJobAlerts, whatsappUpdates, messagesFromSchools } = req.body;
    try {
        const profile = await EmployerProfile.findOneAndUpdate(
            { user: req.user.id },
            { $set: { 
                "settings.notifications.emailJobAlerts": emailJobAlerts,
                "settings.notifications.whatsappUpdates": whatsappUpdates,
                "settings.notifications.messagesFromSchools": messagesFromSchools
            }},
            { new: true }
        );
        res.status(200).json(profile.settings.notifications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const addExperience = async (req, res) => {
    try {
        const profile = await EmployerProfile.findOneAndUpdate({ user: req.user.id }, { $push: { workExperience: req.body } }, { new: true });
        res.status(201).json(profile.workExperience);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateExperience = async (req, res) => {
    try {
        const profile = await EmployerProfile.findOneAndUpdate({ user: req.user.id, "workExperience._id": req.params.expId }, { $set: { "workExperience.$": { ...req.body, _id: req.params.expId } } }, { new: true });
        if (!profile) return res.status(404).json({ message: "Experience not found" });
        res.json(profile.workExperience);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const deleteExperience = async (req, res) => {
    try {
        await EmployerProfile.findOneAndUpdate({ user: req.user.id }, { $pull: { workExperience: { _id: req.params.expId } } });
        res.json({ message: "Experience removed" });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const addEducation = async (req, res) => {
    try {
        const profile = await EmployerProfile.findOneAndUpdate({ user: req.user.id }, { $push: { education: req.body } }, { new: true });
        res.status(201).json(profile.education);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateEducation = async (req, res) => {
    try {
        const profile = await EmployerProfile.findOneAndUpdate({ user: req.user.id, "education._id": req.params.eduId }, { $set: { "education.$": { ...req.body, _id: req.params.eduId } } }, { new: true });
        if (!profile) return res.status(404).json({ message: "Education not found" });
        res.json(profile.education);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const deleteEducation = async (req, res) => {
    try {
        await EmployerProfile.findOneAndUpdate({ user: req.user.id }, { $pull: { education: { _id: req.params.eduId } } });
        res.json({ message: "Education removed" });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const updateSkills = async (req, res) => {
    const { skills } = req.body;
    try {
        const skillIds = await Promise.all(skills.map(async (name) => {
            const skill = await Skill.findOneAndUpdate({ name: name.trim().toLowerCase() }, { $setOnInsert: { name: name.trim().toLowerCase() } }, { upsert: true, new: true });
            return skill._id;
        }));
        const profile = await EmployerProfile.findOneAndUpdate({ user: req.user.id }, { $set: { skills: skillIds } }, { new: true }).populate('skills');
        res.json(profile.skills);
    } catch (error) { res.status(500).json({ message: error.message }); }
};

const uploadFile = async (req, res, fileType) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
    try {
        const folder = `teacher-portal/${fileType}s`;
        const result = await uploadOnS3(req.file.buffer, folder, req.file.mimetype);
        let updateData;
        if (fileType === 'profilePicture') updateData = { profilePicture: { public_id: result.public_id, url: result.url } };
        else if (fileType === 'demoVideo') updateData = { demoVideo: { public_id: result.public_id, url: result.url } };
        else updateData = { $push: { documents: { public_id: result.public_id, url: result.url, name: req.file.originalname } } };
        const profile = await EmployerProfile.findOneAndUpdate({ user: req.user.id }, updateData, { new: true });
        res.json({ message: `${fileType} uploaded!`, url: result.url, profile });
    } catch (error) { res.status(500).json({ message: error.message }); }
};

export const uploadProfilePicture = (req, res) => uploadFile(req, res, 'profilePicture');
export const uploadDemoVideo = (req, res) => uploadFile(req, res, 'demoVideo');
export const uploadDocument = (req, res) => uploadFile(req, res, 'document');

export const getMyApplications = async (req, res) => {
    try {
        const { category } = req.query;
        if (!category) return res.status(400).json({ message: "Category query parameter is required." });
        
        let query = { user: req.user.id };

        if (category === 'offers') {
            query.status = 'offer_extended';
            query['offerLetter.forwardedByAdmin'] = true;
        } else {
            query.category = category;
        }

        const applications = await Application.find(query)
            .populate({ path: 'job', select: 'title schoolName location' })
            .sort({ updatedAt: -1 });
            
        res.status(200).json(applications);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const applyToJob = async (req, res) => {
    try {
        const { jobId } = req.params;
        const existingApplication = await Application.findOne({ user: req.user.id, job: jobId });
        if (existingApplication && existingApplication.category !== 'saved') {
            return res.status(400).json({ message: "You have already applied for this job." });
        }
        const application = await Application.findOneAndUpdate(
            { user: req.user.id, job: jobId },
            { $set: { category: 'applied', status: 'pending_admin_approval', appliedDate: new Date() } },
            { upsert: true, new: true }
        );
        res.status(201).json(application);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const saveJob = async (req, res) => {
    try {
        const { jobId } = req.params;
        const application = await Application.findOneAndUpdate(
            { user: req.user.id, job: jobId },
            { $setOnInsert: { user: req.user.id, job: jobId, category: 'saved', status: 'saved' } },
            { upsert: true, new: true, runValidators: true }
        );
        res.status(200).json(application);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const unsaveJob = async (req, res) => {
    try {
        const { appId } = req.params;
        const application = await Application.findOneAndDelete({ _id: appId, user: req.user.id, category: 'saved' });
        if (!application) return res.status(404).json({ message: "Saved job not found." });
        res.status(200).json({ message: "Job unsaved successfully." });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const updateApplication = async (req, res) => {
    try {
        const { appId } = req.params;
        const { category, status, interviewDetails, offerDetails, action } = req.body;
        let updatePayload = {};
        if (category) updatePayload.category = category;
        if (status) updatePayload.status = status;
        if (interviewDetails) updatePayload.interviewDetails = interviewDetails;
        if (offerDetails) updatePayload.offerDetails = offerDetails;
        if (action === 'accept_offer') { updatePayload = { status: 'hired', category: 'hired' }; }
        if (action === 'decline_offer') { updatePayload = { status: 'rejected', category: 'archived' }; }
        const application = await Application.findOneAndUpdate({ _id: appId, user: req.user.id }, { $set: updatePayload }, { new: true });
        if (!application) return res.status(404).json({ message: "Application not found." });
        res.status(200).json(application);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const withdrawApplication = async (req, res) => {
    try {
        const { appId } = req.params;
        const application = await Application.findOneAndDelete({ _id: appId, user: req.user.id, category: { $ne: 'saved' } });
        if (!application) return res.status(404).json({ message: "Application not found." });
        res.status(200).json({ message: "Application withdrawn successfully." });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const submitAcceptance = async (req, res) => {
    try {
        const { appId } = req.params;
        const { termsAndConditionsAccepted } = req.body;

        if (termsAndConditionsAccepted !== 'true') {
            return res.status(400).json({ message: 'You must accept the terms and conditions.' });
        }
        
        if (!req.files || !req.files.signedAgreement) {
            return res.status(400).json({ message: 'Signed agreement is mandatory.' });
        }

        const application = await Application.findOne({ _id: appId, user: req.user.id });
        if (!application) {
            return res.status(404).json({ message: 'Application not found.' });
        }

        const uploadedDocuments = [];
        if (req.files) {
            for (const key in req.files) {
                const fileArray = req.files[key];
                if (fileArray && fileArray.length > 0) {
                    const file = fileArray[0];
                    const result = await uploadOnS3(file.buffer, `acceptance_documents/${appId}`, file.mimetype);
                    uploadedDocuments.push({
                        name: file.originalname,
                        documentType: key,
                        public_id: result.public_id,
                        url: result.url,
                    });
                }
            }
        }
        
        application.status = 'pending_document_approval';
        application.category = 'hired';
        application.termsAndConditionsAccepted = true;
        application.acceptanceDocuments = uploadedDocuments;

        await application.save();
        res.status(200).json({ success: true, message: 'Offer accepted and documents submitted for verification.', data: application });

    } catch (error) {
        res.status(500).json({ message: 'Server error while submitting acceptance.', error: error.message });
    }
};