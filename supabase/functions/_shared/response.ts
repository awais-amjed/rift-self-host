import { corsHeaders } from "./cors.ts";

export class CustomResponse {
  /**
   * Return a structured error response.
   *
   * @param message       Human-readable description (shown in logs / UI).
   * @param code          Machine-readable error code from `error_codes.ts`.
   *                      Always provide this so clients can switch on it
   *                      instead of doing fragile string matching.
   * @param internalError Optional internal error — logged server-side only,
   *                      NOT sent to the client.
   * @param status        HTTP status code (default 200 for CF convention).
   */
  static error(
    message: string,
    code: string,
    internalError?: unknown,
    status: number = 200,
  ): Response {
    if (internalError !== undefined) {
      console.error(`[${code}] ${message}:`, internalError);
    } else {
      console.error(`[${code}] ${message}`);
    }

    return new Response(
      JSON.stringify({
        success: false,
        error: message,
        code,
      }),
      {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      },
    );
  }

  static success(data: unknown, status: number = 200): Response {
    return new Response(
      JSON.stringify({
        success: true,
        data,
      }),
      {
        status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      },
    );
  }
}
