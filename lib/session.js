import { cookies } from 'next/headers';
import { supabase } from './supabase';
import { verifySession, SESSION_COOKIE } from './jwt';
import { ApiError } from './apiError';

const USER_SELECT = `
  id, uuid, name, email, phone, email_verified_at, status, disabled_reason,
  must_change_password, points_balance, gender,
  role:roles(code),
  user_type:user_types(code),
  governorate:governorates(name_ar),
  institution:institutions(name_ar)
`;

/** يرجّع المستخدم الحالي (أو null) من كوكي الجلسة. معادل Auth::user(). */
export async function currentUser() {
  const token = cookies().get(SESSION_COOKIE)?.value;
  const payload = await verifySession(token);
  if (!payload?.uid) return null;

  const { data, error } = await supabase
    .from('users')
    .select(USER_SELECT)
    .eq('id', payload.uid)
    .is('deleted_at', null)
    .eq('status', 'active')
    .maybeSingle();

  if (error) { console.error('[currentUser]', error); return null; }
  if (!data) return null;

  // PostgREST بيرجّع العلاقات كـ object لو العمود unique، وهنا كلها belongs-to فهتبقى object
  return {
    ...data,
    role: data.role?.code ?? null,
    user_type: data.user_type?.code ?? null,
    governorate: data.governorate?.name_ar ?? null,
    institution: data.institution?.name_ar ?? null,
  };
}

/** لازم يكون مسجّل دخول (ودور معيّن اختياريًا). معادل Auth::need(). */
export async function requireUser(roles = [], allowPwChange = false) {
  const u = await currentUser();
  if (!u) throw new ApiError('unauthorized', 'سجّل دخولك الأول.', 401);
  if (roles.length && !roles.includes(u.role)) {
    throw new ApiError('forbidden', 'مش مسموح لك بالعملية دي.', 403);
  }
  if (!allowPwChange && u.must_change_password) {
    throw new ApiError('must_change_password', 'لازم تغيّر كلمة المرور الأول.', 403);
  }
  return u;
}

export function isStaff(u) {
  return u.role === 'owner' || u.role === 'admin';
}

/** صلاحيات الأدمن التفصيلية: المالك كل حاجة، الأدمن من admin_permissions، غيرهم ولا حاجة. */
export async function perms(u) {
  if (u.role === 'owner') return ['*']; // المالك: كل الصلاحيات دايمًا
  if (u.role !== 'admin') return [];
  const { data, error } = await supabase
    .from('admin_permissions')
    .select('perm')
    .eq('user_id', u.id);
  if (error) { console.error('[perms]', error); return []; }
  return data.map((r) => r.perm);
}

export async function can(perm, u) {
  if (u.role === 'owner') return true;
  const list = await perms(u);
  return list.includes(perm);
}

export async function requireStaff() {
  return requireUser(['owner', 'admin']);
}

/** شكل بيانات المستخدم اللي بيتبعت للفرونت إند. معادل Auth::publicUser(). */
export async function publicUser(u) {
  const { data: shareClaim } = await supabase
    .from('points_ledger')
    .select('id')
    .eq('user_id', u.id)
    .eq('reason', 'share')
    .limit(1)
    .maybeSingle();

  const { data: setting } = await supabase
    .from('settings')
    .select('v')
    .eq('k', 'share_points')
    .maybeSingle();

  return {
    id: u.uuid,
    name: u.name,
    email: u.email,
    role: u.role,
    type: u.user_type,
    gov: u.governorate,
    gender: u.gender,
    phone: u.phone ?? null,
    institution: u.institution ?? null,
    points: u.points_balance,
    must_change_password: !!u.must_change_password,
    email_verified: !!u.email_verified_at,
    share_claimed: !!shareClaim,
    share_points: Math.max(0, parseInt(setting?.v ?? '40', 10)),
    staff: isStaff(u),
    perms: await perms(u),
  };
}
