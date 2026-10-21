import { cookies } from 'next/headers';
import { supabase } from '../../../../lib/supabase';
import { ApiError, errorResponse } from '../../../../lib/apiError';
import { verifyPassword, hashPassword, needsRehash } from '../../../../lib/password';
import { hit as rateHit } from '../../../../lib/rateLimiter';
import { signSession, SESSION_COOKIE, sessionCookieOptions } from '../../../../lib/jwt';
import { log as audit, clientIp } from '../../../../lib/audit';
import { getSetting } from '../../../../lib/settings';
import { publicUser } from '../../../../lib/session';

// هاش وهمي بنستخدمه لما الحساب مش موجود، عشان زمن تنفيذ login يفضل متقارب
// سواء الحساب موجود أو لا (منع User Enumeration بالتوقيت). بيتحسب أول استخدام بس.
let dummyHashPromise = null;
function dummyHash() {
  if (!dummyHashPromise) dummyHashPromise = hashPassword('dummy-password-for-timing');
  return dummyHashPromise;
}

export async function POST(req) {
  try {
    await rateHit('login-ip:' + clientIp(req), 20, 600);

    const b = await req.json();
    const identifierRaw = typeof b.identifier === 'string' ? b.identifier : (typeof b.email === 'string' ? b.email : '');
    const identifier = identifierRaw.trim();
    const pw = typeof b.password === 'string' ? b.password : '';

    if (!identifier || !pw || pw.length > 128 || identifier.length > 190) {
      throw new ApiError('invalid_credentials', 'البيانات أو كلمة المرور غير صحيحة.', 401);
    }

    const isEmail = identifier.includes('@');
    const col = isEmail ? 'email' : 'phone';
    let val = identifier;
    if (isEmail) {
      val = identifier.toLowerCase();
    } else {
      // لازم رقم هاتف صحيح الشكل (نفس رسالة الخطأ القديمة لو ناقص)
      const digits = identifier.replace(/[٠-٩]/g, (d) => '٠١٢٣٤٥٦٧٨٩'.indexOf(d).toString());
      if (!/^01[0-9]{9}$/.test(digits)) {
        throw new ApiError('invalid_credentials', 'رقم الهاتف أو الإيميل أو كلمة المرور غير صحيحة.', 401);
      }
      val = digits;
    }

    await rateHit('login-id:' + val, 10, 600);

    const { data: u } = await supabase
      .from('users')
      .select('id, name, email, email_verified_at, password_hash, status, disabled_reason, failed_logins, locked_until, last_login_ip, deleted_at, role:roles(code)')
      .eq(col, val)
      .maybeSingle();

    const maxFailures = parseInt(await getSetting('max_login_failures', '5'), 10);
    const lockMinutes = parseInt(await getSetting('lockout_minutes', '15'), 10);

    const hashToCheck = u?.password_hash ?? (await dummyHash());
    const pwOk = await verifyPassword(pw, hashToCheck);
    const valid = pwOk && u && u.deleted_at === null;

    if (u && u.locked_until && new Date(u.locked_until).getTime() > Date.now()) {
      await audit(u.id, 'login_failed', 'user', u.id, { reason: 'locked' }, req);
      throw new ApiError('locked', 'الحساب مقفول مؤقتًا بسبب محاولات كتير. حاول بعد شوية.', 423);
    }

    if (!valid) {
      if (u) {
        const newFailed = u.failed_logins + 1;
        const update = { failed_logins: newFailed };
        if (newFailed >= maxFailures) {
          update.locked_until = new Date(Date.now() + lockMinutes * 60000).toISOString();
        }
        await supabase.from('users').update(update).eq('id', u.id);
        await audit(u.id, 'login_failed', 'user', u.id, { attempt: newFailed }, req);
        if (newFailed >= maxFailures) {
          await audit(u.id, 'account_locked', 'user', u.id, { minutes: lockMinutes }, req);
        }
      } else {
        await audit(null, 'login_failed', null, null, { identifier: identifier.slice(0, 3) + '***' }, req);
      }
      throw new ApiError('invalid_credentials', 'رقم الهاتف أو الإيميل أو كلمة المرور غير صحيحة.', 401);
    }

    const role = u.role?.code ?? null;

    if (u.status !== 'active') {
      const why = (u.disabled_reason || '').trim();
      await audit(u.id, 'login_failed', 'user', u.id, { reason: 'suspended' }, req);
      throw new ApiError('suspended', 'الحساب معطّل.' + (why ? ' السبب: ' + why : '') + ' تواصل مع الإدارة.', 403);
    }

    const emailVerifyRequired = (await getSetting('email_verify_required', '0')) === '1';
    if (u.email && !u.email_verified_at && emailVerifyRequired) {
      // TODO: إعادة إرسال رابط التوثيق (Mailer) لسه مش متبنية في المرحلة دي.
      throw new ApiError('email_unverified', 'لازم توثّق بريدك الإلكتروني الأول.', 403);
    }

    if (needsRehash(u.password_hash)) {
      await supabase.from('users').update({ password_hash: await hashPassword(pw) }).eq('id', u.id);
    }

    await supabase
      .from('users')
      .update({
        failed_logins: 0,
        locked_until: null,
        last_login_at: new Date().toISOString(),
        last_login_ip: clientIp(req),
      })
      .eq('id', u.id);

    const token = await signSession(u.id);
    cookies().set(SESSION_COOKIE, token, sessionCookieOptions());
    await audit(u.id, 'user.login', 'user', u.id, null, req);

    // TODO: إشعار بريدي عند الدخول من جهاز/شبكة جديدة (Mailer::loginNotice) لسه مش متبنية.

    const { data: fullUser } = await supabase
      .from('users')
      .select('id, uuid, name, email, phone, email_verified_at, status, must_change_password, points_balance, gender, role:roles(code), user_type:user_types(code), governorate:governorates(name_ar), institution:institutions(name_ar)')
      .eq('id', u.id)
      .single();

    const shaped = {
      ...fullUser,
      role: fullUser.role?.code ?? null,
      user_type: fullUser.user_type?.code ?? null,
      governorate: fullUser.governorate?.name_ar ?? null,
      institution: fullUser.institution?.name_ar ?? null,
    };

    return Response.json({ user: await publicUser(shaped) });
  } catch (err) {
    return errorResponse(err);
  }
}
