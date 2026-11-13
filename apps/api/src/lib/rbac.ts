export type Role = "owner" | "admin" | "analyst" | "viewer";
export type Permission =
  | "read" | "incidents:write" | "investigations:run" | "verdicts:review" | "knowledge:propose" | "knowledge:approve"
  | "rules:write" | "connections:write" | "ingestion:run" | "agents:write" | "members:write" | "audit:read"
  | "operations:read";

const GRANTS: Record<Role, Permission[]> = {
  viewer: ["read"],
  analyst: ["read", "incidents:write", "investigations:run", "verdicts:review", "knowledge:propose", "knowledge:approve"],
  admin: ["read", "incidents:write", "investigations:run", "verdicts:review", "knowledge:propose", "knowledge:approve", "rules:write", "connections:write", "ingestion:run", "agents:write", "audit:read", "operations:read"],
  owner: ["read", "incidents:write", "investigations:run", "verdicts:review", "knowledge:propose", "knowledge:approve", "rules:write", "connections:write", "ingestion:run", "agents:write", "members:write", "audit:read", "operations:read"],
};

export const can = (role: Role | null | undefined, p: Permission) => !!role && GRANTS[role].includes(p);
export const permissionsFor = (role: Role) => GRANTS[role];
