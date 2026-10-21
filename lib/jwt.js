import { SignJWT, jwtVerify } from 'jose';

// ليه JWT بدل session() القديمة بتاعة PHP؟
// Vercel serverless functions ماعندهاش ذاكرة مشتركة بين الطلبات، فمينفعش نسيب
// الجلسة في ملف/متغيّر على السيرفر زي الاستضافة القديمة. الحل القياسي: نوقّع
// معرّف المستخدم (uid) في توكن JWT ونحطه في كوكي httpOnly، ونتحقق منه كل طلب.

const SECRET = new TextEncoder().encode(process.env.SESSION_JWT_SECRET || '');
const SESSION_IDLE_SECONDS = 60 * 60 * 8;        // 8 ساعات خمول (زي app.session_idle القديم)
const SESSION_ABSOLUTE_SECONDS = 60 * 60 * 24 * 7; // أسبوع كحد أقصى مطلق

export const SESSION_COOKIE = 'ps_session';

export async function signSession(uid) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ uid })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setExpirationTime(now + SESSION_ABSOLUTE_SECONDS)
    .sign(SECRET);
}

export async function verifySession(token) {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, SECRET);
    return payload; // { uid, iat, exp }
  } catch {
    return null;
  }
}

export function sessionCookieOptions() {
  // لو الفرونت القديم لسه على InfinityFree والباك إند الجديد على فيرسل (دومين
  // مختلف)، الكوكي لازم SameSite=None (مع Secure) عشان يتبعت في طلبات cross-site.
  // لما الفرونت ينتقل بره حدود نفس الـ Next.js app، رجّعها 'lax' (أأمن).
  const sameSite = process.env.COOKIE_SAMESITE || 'lax';
  return {
    httpOnly: true,
    secure: true,
    sameSite,
    path: '/',
    maxAge: SESSION_ABSOLUTE_SECONDS,
  };
}

export const SESSION_IDLE_SECONDS_EXPORT = SESSION_IDLE_SECONDS;
