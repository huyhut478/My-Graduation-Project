import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { ICONS_PATH, AVATARS_PATH } from './paths.js';

for (const dir of [ICONS_PATH, AVATARS_PATH]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

const iconStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, ICONS_PATH);
  },
  filename: function (req, file, cb) {
    const fieldName = file.fieldname || 'icon';
    const timestamp = Date.now();
    const ext = path.extname(file.originalname) || '.png';
    const filename = `${fieldName}_${timestamp}${ext}`;
    cb(null, filename);
  }
});

const avatarStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, AVATARS_PATH);
  },
  filename: function (req, file, cb) {
    const userId = req.session?.user?.id || 'unknown';
    const timestamp = Date.now();
    const ext = path.extname(file.originalname) || '.png';
    const filename = `avatar_${userId}_${timestamp}${ext}`;
    cb(null, filename);
  }
});

const imageFilter = function (req, file, cb) {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error('Chỉ chấp nhận file ảnh (JPEG, PNG, GIF, WEBP)'));
  }
};

const upload = multer({
  storage: iconStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: imageFilter
});

const uploadAvatar = multer({
  storage: avatarStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: imageFilter
});

export { upload, uploadAvatar, imageFilter };



