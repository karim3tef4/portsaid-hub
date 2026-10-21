import { supabase } from './supabase';

// ملحوظة: الكود القديم عنده كمان activity_log بسلسلة hash للتدقيق (append-only،
// تظهر في لوحة "المالك"). سيبناها للمرحلة الجاية بعد ما نبني لوحة الأدمن نفسها،
// عشان منبنيش منطق عرض/تدقيق من غير حد يستخدمه. audit_logs هنا كافية لتتبع
// محاولات الدخول والتسجيل دلوقتي.
export async function log(actorId, action, entityType, entityId, meta = null, req = null) {
  try {
    await supabase.from('audit_logs').insert({
      actor_id: actorId,
      action,
      entity_type: entityType,
      entity_id: entityId,
      ip: req ? clientIp(req) : null,
      user_agent: req ? req.headers.get('user-agent') : null,
      meta: meta ? JSON.stringify(meta) : null,
    });
  } catch (e) {
    console.error('[audit]', e);
  }
}

/** IP العميل من الطلب. على فيرسل الهيدر الموثوق هو x-forwarded-for. */
export function clientIp(req) {
  const xff = req.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return req.headers.get('x-real-ip') || '0.0.0.0';
}
