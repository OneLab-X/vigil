"use client";
import { useMutation, useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";

let csrf = "";
export function setCsrf(t: string) { csrf = t; }

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public details?: unknown) { super(message); }
}

export async function api<T = any>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = init.method ?? "GET";
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (method !== "GET") headers["x-vigil-csrf"] = csrf;
  const res = await fetch(`/api/v1${path}`, { method, headers, credentials: "same-origin", body: init.body === undefined ? undefined : JSON.stringify(init.body) });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined" && !path.startsWith("/auth/")) window.location.href = "/login";
    throw new ApiError(res.status, json?.error?.code ?? "error", json?.error?.message ?? res.statusText, json?.error?.details);
  }
  return json as T;
}

export const useApi = <T = any>(key: QueryKey, path: string | null, opts: { refetchInterval?: number } = {}) =>
  useQuery<T>({ queryKey: key, queryFn: () => api<T>(path!), enabled: !!path, refetchInterval: opts.refetchInterval });

export function useAct<V = any, R = any>(fn: (v: V) => Promise<R>, invalidate: QueryKey[] = []) {
  const qc = useQueryClient();
  return useMutation({ mutationFn: fn, onSuccess: () => invalidate.forEach((k) => qc.invalidateQueries({ queryKey: k })) });
}
