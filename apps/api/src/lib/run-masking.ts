import { Masker, type MaskState } from "@vigil/core";
import { decrypt, encrypt } from "./crypto.js";

/** Run-scoped token map: stored encrypted on the run, never sent to the model or returned by the API. */
export function loadMasker(run: { masking: string; maskState: string | null }): Masker | null {
  if (run.masking !== "on") return null;
  return new Masker(run.maskState ? (JSON.parse(decrypt(run.maskState)) as MaskState) : null);
}
export const sealMaskState = (m: Masker) => encrypt(JSON.stringify(m.state()));

/** API view of a run: the encrypted token map never leaves the server; stats (counts only) do. */
export function publicRun<T extends { maskState?: string | null }>(r: T): Omit<T, "maskState"> {
  const { maskState: _drop, ...rest } = r;
  return rest;
}
