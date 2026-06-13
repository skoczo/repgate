export interface SystemStatus {
  uptime: string;
  fail_open: boolean;
  l1_cache_entries: number;
  l1_cache_capacity: number;
  l2_cache_entries: number;
  l2_threat_entries: number;
  live_stream_disabled: boolean;
  live_stream_retention_days: number;
}

export interface RepgateEvent {
  id: number;
  ip: string;
  target_host: string;
  target_path: string;
  action: string;
  source: string;
  timestamp: string;
}

export interface IPRecord {
  ip: string;
  status: string;
  score: number;
  source: string;
  checked_at: string;
  expires_at: string;
  reported: boolean;
}

export interface DbRecordsResponse {
  records: IPRecord[];
  total: number;
}

export interface DbQueryParams {
  limit: number;
  offset: number;
  search: string;
  status: string;
  sort_by: string;
  sort_order: 'asc' | 'desc';
}

export async function fetchStatus(): Promise<SystemStatus> {
  const res = await fetch('/api/v1/status');
  if (!res.ok) {
    throw new Error(`HTTP error! Status: ${res.status}`);
  }
  return res.json();
}

export async function fetchEvents(limit: number, beforeId: number | null, action: string): Promise<RepgateEvent[]> {
  const filterParam = action !== 'all' ? `&action=${action}` : '';
  const beforeParam = beforeId !== null ? `&before_id=${beforeId}` : '';
  const res = await fetch(`/api/v1/events?limit=${limit}${beforeParam}${filterParam}`);
  if (!res.ok) {
    throw new Error(`HTTP error! Status: ${res.status}`);
  }
  return res.json();
}

export async function fetchDbRecords(params: DbQueryParams): Promise<DbRecordsResponse> {
  const queryParams = new URLSearchParams({
    limit: params.limit.toString(),
    offset: params.offset.toString(),
    search: params.search,
    status: params.status,
    sort_by: params.sort_by,
    sort_order: params.sort_order,
  });
  const res = await fetch(`/api/v1/db/records?${queryParams.toString()}`);
  if (!res.ok) {
    throw new Error(`HTTP error! Status: ${res.status}`);
  }
  return res.json();
}
