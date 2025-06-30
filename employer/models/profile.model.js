import mongoose from 'mongoose';

const workExperienceSchema = new mongoose.Schema({
  title: { type: String, required: true }, company: { type: String, required: true },
  location: String, duration: String,
});

const educationSchema = new mongoose.Schema({
  degree: { type: String, required: true }, school: { type: String, required: true },
  year: String, percentage: String,
});

const profileSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  name: { type: String, default: '' }, headline: { type: String, default: '' },
  location: { type: String, default: '' }, phone: { type: String, default: '' },
  profilePicture: { public_id: String, url: String },
  demoVideo: { public_id: String, url: String },
  documents: [{ public_id: String, url: String, name: String }],
  isVisible: { type: Boolean, default: true },
  workExperience: [workExperienceSchema],
  education: [educationSchema],
  skills: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Skill' }],
  jobPreferences: { jobType: String, expectedSalary: String, preferredLocation: String, noticePeriod: String, },
  settings: {
    notifications: {
      emailJobAlerts: { type: Boolean, default: true },
      whatsappUpdates: { type: Boolean, default: false },
      messagesFromSchools: { type: Boolean, default: true }
    }
  }
}, { timestamps: true });

export const EmployerProfile = mongoose.model('EmployerProfile', profileSchema);