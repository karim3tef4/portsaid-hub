// معادل app/ApiException.php: خطأ مقصود بكود ورسالة عربية للمستخدم وHTTP status.
export class ApiError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

/** يحوّل أي خطأ لرد JSON موحّد. استخدمها في try/catch حوالين منطق كل route. */
export function errorResponse(err) {
  if (err instanceof ApiError) {
    return Response.json({ error: err.code, message: err.message }, { status: err.status });
  }
  // خطأ غير متوقع: نسجله في اللوج ونرجع رسالة عامة (من غير تفاصيل داخلية للمستخدم)
  console.error('[unexpected]', err);
  return Response.json(
    { error: 'server_error', message: 'حصل خطأ غير متوقع، حاول تاني.' },
    { status: 500 }
  );
}
