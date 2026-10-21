import crypto from 'node:crypto';
import { supabase } from './supabase';
import { ApiError } from './apiError';

/** زي RateLimiter::hit القديم بالظبط، بس بيستدعي دالة Postgres (رياضة ذرّية). */
export async function hit(key, max, windowSec) {
  const bucket = crypto.createHash('sha256').update(key, 'utf8').digest('hex');
  const { data, error } = await supabase.rpc('rate_limit_hit', {
    p_bucket: bucket,
    p_window_sec: windowSec,
  });
  if (error) {
    console.error('[rateLimiter]', error);
    return; // لو الدالة فشلت لأي سبب، منمنعش المستخدم من المتابعة (fail-open زي القديم تقريبًا)
  }
  if (typeof data === 'number' && data > max) {
    throw new ApiError('rate_limited', 'محاولات كتير، استنى شوية وحاول تاني.', 429);
  }
}
