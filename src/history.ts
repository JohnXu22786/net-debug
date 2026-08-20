/**
 * In-memory ring buffer for per-session request/response history.
 *
 * Holds at most {@link HistoryStore.maxEntries} exchanges. When full, the
 * oldest entry is evicted to make room for the newest, so the store always
 * retains the most recent `maxEntries` requests (no unbounded growth).
 */
import type { HistoryEntry, HistoryResponse, HistorySummary } from './types.js';

export interface HistoryStats {
  /** Number of entries currently retained. */
  count: number;
  /** Ring-buffer capacity. */
  capacity: number;
  /** Sum of `recordedBytes` across retained entries. */
  totalBytes: number;
}

export class HistoryStore {
  private readonly buffer: (HistoryEntry | undefined)[];
  private readonly maxEntries: number;
  private head = 0; // index of the oldest entry
  private count = 0;
  private totalBytes = 0;

  /** `capacity <= 0` stores nothing (the "hold at most `capacity`" contract). */
  constructor(capacity: number) {
    this.maxEntries = Math.max(0, Math.floor(capacity));
    this.buffer = new Array<HistoryEntry | undefined>(Math.max(1, this.maxEntries));
  }

  /** Append an exchange; evicts the oldest when at capacity. Id must be unique. */
  push(entry: HistoryEntry): void {
    if (this.maxEntries === 0) return;
    if (this.count === this.maxEntries) {
      const evicted = this.buffer[this.head];
      if (evicted) this.totalBytes -= evicted.recordedBytes;
      this.buffer[this.head] = entry;
      this.head = (this.head + 1) % this.maxEntries;
    } else {
      this.buffer[(this.head + this.count) % this.maxEntries] = entry;
      this.count += 1;
    }
    this.totalBytes += entry.recordedBytes;
  }

  /** Look up one entry by id; `undefined` when evicted or unknown. */
  get(id: string): HistoryEntry | undefined {
    for (let i = 0; i < this.count; i += 1) {
      const entry = this.buffer[(this.head + i) % this.buffer.length];
      if (entry?.id === id) return entry;
    }
    return undefined;
  }

  /** Newest-first summaries (copies, not live references). */
  list(): HistorySummary[] {
    const summaries: HistorySummary[] = [];
    for (let i = this.count - 1; i >= 0; i -= 1) {
      const entry = this.buffer[(this.head + i) % this.buffer.length];
      if (!entry) continue;
      summaries.push({
        id: entry.id,
        startedAt: entry.startedAt,
        method: entry.request.method,
        url: entry.request.url,
        status: entry.response?.status,
        outcome: entry.outcome,
        errorCode: entry.error?.code,
        durationMs: entry.durationMs,
        bodySizeBytes: entry.response?.bodySizeBytes ?? 0,
        recordedBytes: entry.recordedBytes,
      });
    }
    return summaries;
  }

  /** Remove every entry; returns how many were cleared. */
  clear(): number {
    const cleared = this.count;
    for (let i = 0; i < this.buffer.length; i += 1) this.buffer[i] = undefined;
    this.head = 0;
    this.count = 0;
    this.totalBytes = 0;
    return cleared;
  }

  stats(): HistoryStats {
    return { count: this.count, capacity: this.maxEntries, totalBytes: this.totalBytes };
  }
}

/** Copy the response snapshot stored on a history entry. */
export function copyHistoryResponse(response: HistoryResponse): HistoryResponse {
  return { ...response, headers: { ...response.headers }, redirects: [...response.redirects] };
}
