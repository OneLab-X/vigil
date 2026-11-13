import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
export const cn = (...c: ClassValue[]) => twMerge(clsx(c));
export const fmtTime = (s?: string | null) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" }) : "—");
export const ago = (s?: string | null) => {
  if (!s) return "never";
  const d = (Date.now() - new Date(s).getTime()) / 1000;
  if (d < 60) return `${Math.round(d)}s ago`;
  if (d < 3600) return `${Math.round(d / 60)}m ago`;
  if (d < 86400) return `${Math.round(d / 3600)}h ago`;
  return `${Math.round(d / 86400)}d ago`;
};
export const pct = (n?: number | null) => (n === null || n === undefined ? "—" : `${Math.round(n * 100)}%`);
