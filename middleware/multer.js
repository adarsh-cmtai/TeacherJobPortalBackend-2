import multer from 'multer';

const storage = multer.memoryStorage();

export const upload = multer({ storage: storage });

export const singleUpload = multer({ storage }).single('image');

export const agreementUpload = multer({ storage }).single('agreement');

export const documentUploads = multer({ storage }).fields([
    { name: 'signedAgreement', maxCount: 1 },
    { name: 'aadhar', maxCount: 1 },
    { name: 'pan', maxCount: 1 },
    { name: 'result', maxCount: 1 },
    { name: 'experience', maxCount: 1 }
]);