import { getSetting } from './settingsService.js';

const loginAttempts = new Map(); // email -> { count, lockedUntil, reason }

async function getLockoutSettings() {
  const maxAttempts = parseInt(await getSetting('lockout_max_attempts', '3'), 10) || 3;
  const durationMinutes = parseInt(await getSetting('lockout_duration_minutes', '5'), 10) || 5;
  const reason = await getSetting('lockout_reason', 'Tài khoản đã bị khóa do nhập sai mật khẩu quá nhiều lần. Vui lòng thử lại sau.');
  return {
    maxAttempts,
    durationMs: durationMinutes * 60 * 1000,
    reason
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [email, attempt] of loginAttempts.entries()) {
    if (attempt.lockedUntil > 0 && attempt.lockedUntil < now) {
      loginAttempts.delete(email);
    }
  }
}, 60 * 60 * 1000);

export { loginAttempts, getLockoutSettings };




