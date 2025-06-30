import asyncHandler from "express-async-handler";
import Resource from "../models/resource.model.js";

import { uploadOnS3, deleteFromS3 } from "../../config/s3Config.js";

export const createResource = asyncHandler(async (req, res) => {
  const { title, category, content, status, isFeatured, readTime } = req.body;

  if (!title || !category || !content || !readTime) {
    res.status(400);
    throw new Error("Please fill all required fields");
  }

  if (!req.file) {
    res.status(400);
    throw new Error("Feature image is required");
  }

  const s3Response = await uploadOnS3(
    req.file.buffer,
    "resources",
    req.file.mimetype
  );

  const resource = await Resource.create({
    title,
    category,
    content,
    status,
    isFeatured,
    readTime,
    imageUrl: s3Response.url,
    author: req.user.id,
  });

  res.status(201).json(resource);
});

export const updateResource = asyncHandler(async (req, res) => {
  const resource = await Resource.findById(req.params.id);

  if (!resource) {
    res.status(404);
    throw new Error("Resource not found");
  }

  const updatedData = { ...req.body };

  if (req.file) {
    if (resource.imageUrl) {
      const oldKey = resource.imageUrl.split(".com/")[1];
      if (oldKey) {
        await deleteFromS3(oldKey).catch((err) =>
          console.error(
            "Failed to delete old S3 object, continuing update...",
            err
          )
        );
      }
    }

    const s3Response = await uploadOnS3(
      req.file.buffer,
      "resources",
      req.file.mimetype
    );
    updatedData.imageUrl = s3Response.url;
  }

  const updatedResource = await Resource.findByIdAndUpdate(
    req.params.id,
    updatedData,
    { new: true, runValidators: true }
  );

  res.status(200).json(updatedResource);
});

export const deleteResource = asyncHandler(async (req, res) => {
  const resource = await Resource.findById(req.params.id);

  if (!resource) {
    res.status(404);
    throw new Error("Resource not found");
  }

  if (resource.imageUrl) {
    const key = resource.imageUrl.split(".com/")[1];
    if (key) {
      try {
        await deleteFromS3(key);
      } catch (s3Error) {
        console.error("Error deleting image from S3:", s3Error);
      }
    }
  }

  await resource.deleteOne();

  res
    .status(200)
    .json({ id: req.params.id, message: "Resource deleted successfully" });
});

export const getResources = asyncHandler(async (req, res) => {
  const resources = await Resource.find({ status: "published" }).sort({
    createdAt: -1,
  });
  res.status(200).json(resources);
});

export const getResourceById = asyncHandler(async (req, res) => {
  // This populate call will now work correctly
  const resource = await Resource.findById(req.params.id).populate({
  path: "author",
  select: "email role", // Add "name" if your User model includes it
  strictPopulate: false
});



  if (resource) {
    res.status(200).json(resource);
  } else {
    res.status(404);
    throw new Error("Resource not found");
  }
});
