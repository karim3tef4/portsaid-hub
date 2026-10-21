import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

// الكود القديم (PHP) كان بيعمل: base64(sha256(password)) الأول، وبعدين bcrypt/argon2
// على الناتج ده — عشان يتفادى حد الـ72 بايت اللي bcrypt بيقطع عنده. لازم نفس الخطوة
// هنا بالظبط عشان أي حساب قديم مهاجَر يفضل يقدر يسجّل دخول بكلمة السر القديمة.
function preHash(pw) {
  return crypto.createHash('sha256').update(pw, 'utf8').digest('base64');
}

export async function hashPassword(pw) {
  return bcrypt.hash(preHash(pw), 12);
}

export async function verifyPassword(pw, hash) {
  if (!hash) return false;
  // PHP أحيانًا بيطلع هاش بصيغة $2y$ (bcrypt قديم)؛ bcryptjs بيفهم $2a$/$2b$ بس،
  // فنحوّل $2y$ لـ $2b$ قبل المقارنة (نفس خوارزمية bcrypt، فرق في العلامة بس).
  const normalized = hash.startsWith('$2y$') ? '$2b$' + hash.slice(4) : hash;
  try {
    return await bcrypt.compare(preHash(pw), normalized);
  } catch {
    return false;
  }
}

export function needsRehash(hash) {
  // عندنا دايمًا cost=12 بالضبط؛ أي حاجة مختلفة (مثلاً هاش argon2 قديم) تتعاد.
  const m = /^\$2[aby]\$(\d+)\$/.exec(hash || '');
  return !m || parseInt(m[1], 10) !== 12;
}
