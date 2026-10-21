import { createClient } from '@supabase/supabase-js';

// ملاحظة أمان: الملف ده بيستخدم service_role key اللي بيتخطى RLS بالكامل.
// استورده بس جوه app/api/** (كود سيرفر)، وأبدًا في أي component بيتبعت للمتصفح.
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error('SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY مفقودين من متغيرات البيئة.');
}

export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);
