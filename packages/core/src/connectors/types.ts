import type { CanonicalEvent, ConnectorId } from "../types.js";

export interface PermissionCheck {
  permission: string;
  granted: boolean;
  required: boolean;
  /** true when the permission grants write/admin capability we do NOT want */
  excessive?: boolean;
}

export interface ConnectionTestResult {
  ok: boolean;
  provider: ConnectorId;
  accountRef: string;
  principal: string | null;
  credentialType: string;
  checks: PermissionCheck[];
  readOnly: boolean; // false when any excessive permission was granted
  warnings: string[];
  errors: string[];
  sampleReadOk: boolean;
  testedAt: string;
}

export interface DiscoveredSource {
  sourceType: string;
  name: string;
  filter: string | null;
  description: string;
  available: boolean; // logs observed / API reachable
  recommended: boolean;
  meta?: Record<string, unknown>;
}

export interface ListEventsQuery {
  sourceType: string;
  filter: string | null;
  start: Date;
  end: Date;
  pageToken?: string | null;
  pageSize?: number;
}

export interface EventPage {
  raw: unknown[];
  nextPageToken: string | null;
}

export interface Checkpoint {
  watermark: string | null;
  pageToken: string | null;
}

export interface CheckpointStore {
  get(sourceId: string): Promise<Checkpoint | null>;
  save(sourceId: string, cp: Checkpoint): Promise<void>;
}

export interface StreamHandle { stop(): Promise<void> }
export type StreamHandler = (raw: unknown) => Promise<void>;

/**
 * Provider-independent connector contract. Implementations must be read-only: no method may
 * create, modify or delete anything in the customer's cloud or log platform.
 */
export interface CloudConnector {
  readonly provider: ConnectorId;
  connect(): Promise<void>;
  testConnection(): Promise<ConnectionTestResult>;
  discoverSources(): Promise<DiscoveredSource[]>;
  listEvents(q: ListEventsQuery): Promise<EventPage>;
  /** Normalize one raw record produced by listEvents for this source. */
  normalize(raw: unknown, sourceType: string): CanonicalEvent;
  startStreaming?(handler: StreamHandler): Promise<StreamHandle>;
  getCheckpoint(sourceId: string): Promise<Checkpoint | null>;
  saveCheckpoint(sourceId: string, cp: Checkpoint): Promise<void>;
  disconnect(): Promise<void>;
}

export class ConnectorError extends Error {
  constructor(message: string, readonly status?: number, readonly retryable = false, readonly retryAfterMs?: number) {
    super(message);
  }
}
