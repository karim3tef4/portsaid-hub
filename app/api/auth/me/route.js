import { errorResponse } from '../../../../lib/apiError';
import { requireUser, publicUser } from '../../../../lib/session';

export async function GET() {
  try {
    // allowPwChange = true: زي القديم، يسمح يرجّع بيانات المستخدم حتى لو لسه
    // لازم يغيّر كلمة السر، عشان الفرونت يعرف يوجّهه لصفحة التغيير.
    const u = await requireUser([], true);
    // TODO: استرجاع نقاط الكوبونات المنتهية (Rewards::refundExpired) لسه مش متبني
    // — هيتضاف مع موديول Rewards في المرحلة الجاية.
    return Response.json({ user: await publicUser(u) });
  } catch (err) {
    return errorResponse(err);
  }
}
