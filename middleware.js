import { NextResponse } from 'next/server';

// فعّلها بس وانت في المرحلة الانتقالية (الفرونت القديم على InfinityFree لسه بيكلم
// الـ API الجديد على فيرسل). حط دومين الموقع القديم في ALLOWED_ORIGIN بالظبط
// (بروتوكول + دومين، من غير / في الآخر)، وامسح المتغيّر ده لما الفرونت ينتقل
// بالكامل لنفس مشروع Next.js (مفيش وقتها cross-origin أصلًا).
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';

export function middleware(req) {
  if (!req.nextUrl.pathname.startsWith('/api/')) return NextResponse.next();

  const origin = req.headers.get('origin') || '';
  const allow = ALLOWED_ORIGIN && origin === ALLOWED_ORIGIN;

  if (req.method === 'OPTIONS') {
    const res = new NextResponse(null, { status: 204 });
    if (allow) {
      res.headers.set('Access-Control-Allow-Origin', origin);
      res.headers.set('Access-Control-Allow-Credentials', 'true');
      res.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.headers.set('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token');
    }
    return res;
  }

  const res = NextResponse.next();
  if (allow) {
    res.headers.set('Access-Control-Allow-Origin', origin);
    res.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  return res;
}

export const config = { matcher: '/api/:path*' };
