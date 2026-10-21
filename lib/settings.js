import { supabase } from './supabase';

export async function getSetting(key, fallback) {
  const { data, error } = await supabase.from('settings').select('v').eq('k', key).maybeSingle();
  if (error || !data) return fallback;
  return data.v;
}
