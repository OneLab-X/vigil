import { describe, it, expect } from "vitest";
import { Masker } from "../src/masking.js";

const ev = {
  event_id: "11111111-1111-4111-8111-111111111111", event_timestamp: "2026-11-11T10:00:00.000Z",
  source_ip: "34.120.5.6", destination_ip: "10.0.0.7", principal: "123456789012-compute@developer.gserviceaccount.com",
  account: "example-project", resource_id: "projects/example-project/services/example-service", url_path: "/api/login",
  user_agent: "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
};

describe("masking", () => {
  it("masks known fields with typed, hinted tokens and leaves ids/timestamps/paths alone", () => {
    const m = new Masker();
    const out = m.mask(ev);
    expect(out.source_ip).toBe("[[IP_1:public]]");
    expect(out.destination_ip).toBe("[[IP_2:private]]");
    expect(out.principal).toBe("[[SVC_1:gcp]]");
    expect(out.account).toBe("[[ACCOUNT_1:gcp]]");
    expect(out.resource_id).toBe("[[RESOURCE_1]]");
    expect(out.event_id).toBe(ev.event_id);
    expect(out.event_timestamp).toBe(ev.event_timestamp);
    expect(out.url_path).toBe("/api/login");
    expect(out.user_agent).toBe(ev.user_agent); // Chrome/120.0.0.0 is not an IP
  });

  it("is consistent across calls and masks the same values inside free text", () => {
    const m = new Masker();
    m.mask(ev);
    const text = m.mask({ title: "Unusual IAM activity (principal=123456789012-compute@developer.gserviceaccount.com) from 34.120.5.6 in example-project" });
    expect(text.title).toBe("Unusual IAM activity (principal=[[SVC_1:gcp]]) from [[IP_1:public]] in [[ACCOUNT_1:gcp]]");
    expect(JSON.stringify(m.mask(ev))).toBe(JSON.stringify(m.mask(ev)));
  });

  it("detects new values in raw payloads: emails, ARNs, IPv6, project paths", () => {
    const m = new Masker();
    const raw = m.mask({ protoPayload: { authenticationInfo: { principalEmail: "alice@example.com" }, requestMetadata: { callerIp: "2001:4860:4860::8888" },
      resourceName: "projects/other-proj-1/serviceAccounts/x", note: "assumed arn:aws:iam::123456789012:role/Admin from 192.168.1.20" } });
    const s = JSON.stringify(raw);
    for (const real of ["alice@example.com", "2001:4860:4860::8888", "other-proj-1", "123456789012", "192.168.1.20"]) expect(s).not.toContain(real);
    expect(s).toContain("[[EMAIL_1]]");
    expect(s).toContain("[[ROLE_1:aws]]");
    expect(s).toContain("[[IP_2:private]]");
    expect(s).toContain(":public]]");
  });

  it("seeded tenant accounts are masked wherever they appear", () => {
    const m = new Masker();
    m.seed([{ kind: "ACCOUNT", value: "example-project", hint: "gcp" }]);
    expect(m.maskText("namespaces/example-project/services/x")).toBe("namespaces/[[ACCOUNT_1:gcp]]/services/x");
  });

  it("never rewrites inside an existing token", () => {
    const m = new Masker();
    m.mask({ principal: "x@p.iam.gserviceaccount.com" });
    m.seed([{ kind: "ACCOUNT", value: "gcp" }]);
    expect(m.maskText("[[SVC_1:gcp]] in gcp")).toBe("[[SVC_1:gcp]] in [[ACCOUNT_1]]");
  });

  it("primary_entity {field,value} objects are masked by field", () => {
    const m = new Masker();
    expect(m.mask({ primary_entity: { field: "sourceIp", value: "8.8.8.8" } })).toEqual({ primary_entity: { field: "sourceIp", value: "[[IP_1:public]]" } });
  });

  it("unmask restores values (hint optional) and reports invented tokens; state round-trips", () => {
    const m = new Masker();
    m.mask(ev);
    const restored = new Masker(JSON.parse(JSON.stringify(m.state())));
    const r = restored.unmask({ summary: "[[SVC_1:gcp]] acted from [[IP_1]] on [[RESOURCE_1]]; also [[IP_9:public]]", list: ["[[ACCOUNT_1:gcp]]"] });
    expect(r.value.summary).toBe("123456789012-compute@developer.gserviceaccount.com acted from 34.120.5.6 on projects/example-project/services/example-service; also [[IP_9:public]]");
    expect(r.value.list).toEqual(["example-project"]);
    expect(r.unknownTokens).toEqual(["[[IP_9:public]]"]);
  });

  it("stats count masked values per kind", () => {
    const m = new Masker();
    m.mask(ev);
    expect(m.stats()).toEqual({ IP: 2, SVC: 1, ACCOUNT: 1, RESOURCE: 1 });
  });
});
