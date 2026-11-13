export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly details?: unknown) { super(message); }
}
export const notFound = (what = "resource") => new ApiError(404, "not_found", `${what} not found`);
export const forbidden = (msg = "forbidden") => new ApiError(403, "forbidden", msg);
export const badRequest = (msg: string, details?: unknown) => new ApiError(400, "bad_request", msg, details);
export const conflict = (msg: string) => new ApiError(409, "conflict", msg);
