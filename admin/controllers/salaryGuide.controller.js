import { SalaryGuide } from "../models/salaryGuide.model.js";

export const createSalaryGuide = async (req, res) => {
  try {
    const {
      jobTitle,
      category,
      averageSalary,
      salaryRange,
      jobDescription,
      commonSkills,
      relatedProfiles,
    } = req.body;
    const newSalaryGuide = await SalaryGuide.create({
      jobTitle,
      category,
      averageSalary,
      salaryRange,
      jobDescription,
      commonSkills,
      relatedProfiles,
    });
    res.status(201).json({ success: true, data: newSalaryGuide });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

// --- YAHAN BADLAAV KIYA GAYA HAI ---
export const getAllSalaryGuides = async (req, res) => {
  try {
    // .select() ko hata diya gaya hai taaki saari details aayen
    const guides = await SalaryGuide.find({});
    res.status(200).json({ success: true, count: guides.length, data: guides });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const getSalaryGuideById = async (req, res) => {
  try {
    const guide = await SalaryGuide.findById(req.params.id).populate(
      "relatedProfiles",
      "jobTitle category"
    );
    if (!guide) {
      return res
        .status(404)
        .json({ success: false, message: "Salary guide not found." });
    }
    res.status(200).json({ success: true, data: guide });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const updateSalaryGuide = async (req, res) => {
  try {
    const guide = await SalaryGuide.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
    if (!guide) {
      return res
        .status(404)
        .json({ success: false, message: "Salary guide not found." });
    }
    res.status(200).json({ success: true, data: guide });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

export const deleteSalaryGuide = async (req, res) => {
  try {
    const guide = await SalaryGuide.findByIdAndDelete(req.params.id);
    if (!guide) {
      return res
        .status(404)
        .json({ success: false, message: "Salary guide not found." });
    }
    res
      .status(200)
      .json({ success: true, message: "Salary guide deleted successfully." });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
