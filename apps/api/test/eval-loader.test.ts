/** VigilBench loader against the test database, and the eval-mode guard on agent runs. */
import { beforeAll, describe, expect, it } from "vitest";
import { getDb } from "../src/db.js";
import { builtinCases } from "../src/eval/cases.js";
import { loadCase } from "../src/eval/loader.js";
import { startAgentRun } from "../src/services/investigation.js";
import { resetDb } from "./helpers.js";

beforeAll(async () => { await resetDb(); });

describe("eval loader", () => {
  it("loads a seed case into a fresh tenant and runs detection", async () => {
    const c = builtinCases(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "seed.gcp-bruteforce-success")!;
    const l = await loadCase(getDb(), c, "test");
    expect(l.recordEventIds).toHaveLength(c.records.length);
    expect(l.recordEventIds.every(Boolean)).toBe(true);
    expect(l.firedRules).toContain("VGL-AUTH-001");
    expect(l.primaryIncidentId).toBeTruthy();
    expect(l.canaries).toEqual(expect.arrayContaining(["example-project", "198.51.100.77"]));
  });

  it("knowledge seeded after detection does not suppress the case", async () => {
    const c = builtinCases(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "seed.gcp-terraform-sa-key")!;
    const l = await loadCase(getDb(), c, "test");
    expect(l.primaryIncidentId).toBeTruthy();
    const before = await loadCase(getDb(), { ...c, knowledge: c.knowledge.map((k) => ({ ...k, timing: "before_detection" as const })) }, "test");
    expect(before.primaryIncidentId).toBeNull();
    expect(before.suppressedRules.length).toBeGreaterThan(0);
  });

  it("refuses evaluation flags outside eval mode", async () => {
    const c = builtinCases(new Date(Date.now() - 2 * 3600_000)).find((x) => x.id === "seed.gcp-recon-404")!;
    const l = await loadCase(getDb(), c, "test");
    await expect(startAgentRun(getDb(), l.tenantId, l.primaryIncidentId!, "investigation_analyst", null, { evalFlags: ["no_envelope"] }))
      .rejects.toMatchObject({ code: "eval_mode_required" });
  });
});
