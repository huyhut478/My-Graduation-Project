import path from 'path';
import fs from 'fs';

const ROOT_DIR = path.resolve(process.cwd());
const VIEWS_PATH = path.join(ROOT_DIR, 'views');
const PUBLIC_PATH = path.join(ROOT_DIR, 'public');
const DATA_PATH = path.join(ROOT_DIR, 'data');
const ICONS_PATH = path.join(PUBLIC_PATH, 'img', 'icons');
const AVATARS_PATH = path.join(PUBLIC_PATH, 'img', 'avatars');

// Ensure required directories exist
for (const dir of [DATA_PATH, ICONS_PATH, AVATARS_PATH]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export { ROOT_DIR, VIEWS_PATH, PUBLIC_PATH, DATA_PATH, ICONS_PATH, AVATARS_PATH };



