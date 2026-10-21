import { cookies } from 'next/headers';
import { errorResponse } from '../../../../lib/apiError';
import { currentUser } from '../../../../lib/session';
import { log as audit } from '../../../../lib/audit';
import { SESSION_COOKIE } from '../../../../lib/jwt';

export async function POST(req) {
  try {
    const u = await currentUser();
    if (u) await audit(u.id, 'user.logout', 'user', u.id, null, req);
    cookies().delete(SESSION_COOKIE);
    return Response.json({ bye: true });
  } catch (err) {
    return errorResponse(err);
  }
}
