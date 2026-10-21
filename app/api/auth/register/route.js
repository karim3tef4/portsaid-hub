import { cookies } from 'next/headers';
import { supabase } from '../../../../lib/supabase';
import { ApiError, errorResponse } from '../../../../lib/apiError';
import * as V from '../../../../lib/validators';
import { hashPassword } from '../../../../lib/password';
import { hit as rateHit } from '../../../../lib/rateLimiter';
import { signSession, SESSION_COOKIE, sessionCookieOptions } from '../../../../lib/jwt';
import { log as audit, clientIp } from '../../../../lib/audit';
import { publicUser } from '../../../../lib/session';

export async function POST(req) {
  try {
    await rateHit('reg:' + clientIp(req), 5, 3600);

    const b = await req.json();
    const name = V.name(b.name);
    const phone = V.phone(b.phone);
    if (!b.email || String(b.email).trim() === '') {
      throw new ApiError('validation', 'البريد الإلكتروني إجباري عشان توصلك رسائل الموقع.', 422);
    }
    const email = V.email(b.email);
    const pw = V.password(b.password, email, name);
    const gender = V.oneOf(b.gender, ['male', 'female'], 'الجنس');
    const userType = V.oneOf(b.user_type, ['student', 'visitor', 'local'], 'النوع');

    // المحافظة (اختياري، إجباري ضمنيًا لو "من بورسعيد")
    let governorateId = null;
    if (b.governorate && String(b.governorate).trim() !== '') {
      const govName = V.str(b.governorate, 2, 50, 'المحافظة');
      const { data: g } = await supabase.from('governorates').select('id').eq('name_ar', govName).maybeSingle();
      if (!g) throw new ApiError('validation', 'المحافظة غير صحيحة.', 422);
      governorateId = g.id;
    }
    if (userType === 'local' && governorateId === null) {
      const { data: pg } = await supabase.from('governorates').select('id').eq('name_ar', 'بورسعيد').maybeSingle();
      governorateId = pg?.id ?? null;
    }

    const { data: typeRow } = await supabase.from('user_types').select('id').eq('code', userType).single();

    let institutionId = null;
    let idCardB64 = null;
    if (userType === 'student') {
      const instName = V.str(b.institution, 2, 120, 'الكلية أو المدرسة');
      const { data: inst } = await supabase
        .from('institutions').select('id').eq('name_ar', instName).eq('is_active', true).maybeSingle();
      if (!inst) throw new ApiError('validation', 'اختر الكلية أو المدرسة من القائمة.', 422);
      institutionId = inst.id;
      if (!b.id_card || String(b.id_card).trim() === '') {
        throw new ApiError('validation', 'ارفع صورة الكارنيه عشان نفعّل خصومات الطلبة بعد المراجعة.', 422);
      }
      // TODO: الكود القديم كان بيضغط/يحوّل الصورة لـ JPEG بـ ImageUtil::toJpegB64 (حد أقصى 1400px، جودة 80%).
      // لسه مش متحول هنا؛ الصورة بتتخزن زي ما استلمناها. لو الحجم مشكلة، ضغطها من الفرونت قبل الإرسال مؤقتًا.
      idCardB64 = String(b.id_card);
    }

    const { data: roleRow } = await supabase.from('roles').select('id').eq('code', 'user').single();
    const passwordHash = await hashPassword(pw);

    const { data: inserted, error: insertErr } = await supabase
      .from('users')
      .insert({
        name, email, phone,
        password_hash: passwordHash,
        gender,
        user_type_id: typeRow.id,
        governorate_id: governorateId,
        institution_id: institutionId,
        role_id: roleRow.id,
        last_login_at: new Date().toISOString(),
        last_login_ip: clientIp(req),
      })
      .select('id, uuid')
      .single();

    if (insertErr) {
      if (insertErr.code === '23505') { // unique_violation
        if (insertErr.message?.includes('users_phone_key')) {
          throw new ApiError('phone_taken', 'رقم الهاتف ده مسجّل قبل كده.', 409);
        }
        throw new ApiError('email_taken', 'الإيميل ده مسجّل قبل كده.', 409);
      }
      throw insertErr;
    }

    await audit(inserted.id, 'user.register', 'user', inserted.id, null, req);

    if (idCardB64 !== null) {
      await supabase.from('id_verifications').insert({ user_id: inserted.id, img_b64: idCardB64 });
    }

    // TODO: إرسال رابط توثيق البريد (Profile::issueVerification + Mailer) لسه مش متبني في المرحلة دي.

    const token = await signSession(inserted.id);
    cookies().set(SESSION_COOKIE, token, sessionCookieOptions());

    const { data: fullUser } = await supabase
      .from('users')
      .select('id, uuid, name, email, phone, email_verified_at, status, must_change_password, points_balance, gender, role:roles(code), user_type:user_types(code), governorate:governorates(name_ar), institution:institutions(name_ar)')
      .eq('id', inserted.id)
      .single();

    const shaped = {
      ...fullUser,
      role: fullUser.role?.code ?? null,
      user_type: fullUser.user_type?.code ?? null,
      governorate: fullUser.governorate?.name_ar ?? null,
      institution: fullUser.institution?.name_ar ?? null,
    };

    return Response.json({ user: await publicUser(shaped) }, { status: 201 });
  } catch (err) {
    return errorResponse(err);
  }
}
