import { ApiError } from './apiError';

function bad(msg) {
  return new ApiError('validation', msg, 422);
}

function str(v, min, max, label = 'الحقل') {
  if (typeof v !== 'string') throw bad(`${label} مطلوب.`);
  const cleaned = v.replace(/\s+/gu, ' ').trim();
  const len = [...cleaned].length; // يحسب أحرف يونيكود صح (زي mb_strlen)
  if (len < min || len > max) throw bad(`${label} لازم يكون من ${min} إلى ${max} حرف.`);
  if (/[\x00-\x1F\x7F]/u.test(cleaned)) throw bad(`${label} فيه رموز غير مسموحة.`);
  return cleaned;
}

export function name(v) {
  const n = str(v, 2, 100, 'الاسم');
  if (!/^[\p{L}\p{M}][\p{L}\p{M} .'-]*$/u.test(n)) throw bad('الاسم فيه رموز غير مسموحة.');
  return n;
}

export function email(v) {
  const e = str(v, 5, 190, 'الإيميل').toLowerCase();
  // تحقق بسيط وكافٍ (زي FILTER_VALIDATE_EMAIL)
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw bad('اكتب إيميل صحيح.');
  return e;
}

const ARABIC_DIGITS = { '٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4', '٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9' };

export function phone(v) {
  if (typeof v !== 'string' || v.trim() === '') throw bad('اكتب رقم الهاتف.');
  let p = v.trim();
  p = p.replace(/[٠-٩]/g, (d) => ARABIC_DIGITS[d]);
  if (/\D/.test(p)) throw bad('رقم الهاتف لازم يكون أرقام بس.');
  if (p.length < 11) throw bad('رقم الهاتف ناقص: لازم 11 رقم.');
  if (!/^01[0-9]{9}$/.test(p)) throw bad('رقم الهاتف لازم يكون 11 رقم ويبدأ بـ 01.');
  return p;
}

const WEAK_PASSWORDS = new Set([
  '12345678', '123456789', '1234567890', 'password', 'password1',
  'qwerty123', 'iloveyou', '11111111', 'abcd1234', 'admin123',
]);

export function password(v, emailVal = '', nameVal = '') {
  if (typeof v !== 'string' || v.length < 8 || v.length > 128) {
    throw bad('كلمة المرور لازم تكون من 8 إلى 128 حرف.');
  }
  const low = v.toLowerCase();
  if (WEAK_PASSWORDS.has(low) || low === emailVal || low === nameVal.toLowerCase()) {
    throw bad('كلمة المرور ضعيفة، اختار حاجة أصعب.');
  }
  return v;
}

export function oneOf(v, allowed, label = 'القيمة') {
  if (typeof v !== 'string' || !allowed.includes(v)) throw bad(`${label} غير صحيح.`);
  return v;
}

export { str, bad };
