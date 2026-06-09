<script lang="ts">
  import { onMount } from 'svelte';
  import { fetchDbRecords, type IPRecord } from './api';
  import Badge from './Badge.svelte';
  import SourcePill from './SourcePill.svelte';

  let dbRecords = $state<IPRecord[]>([]);
  let dbTotal = $state<number>(0);
  let dbLimit = $state<number>(25);
  let dbOffset = $state<number>(0);
  let dbSearch = $state<string>('');
  let dbStatus = $state<string>('');
  let dbSortBy = $state<string>('expires_at');
  let dbSortOrder = $state<'asc' | 'desc'>('desc');
  let dbLoading = $state<boolean>(false);
  let dbError = $state<string | null>(null);
  let nowTime = $state<number>(Date.now());

  // Time remaining calculator helper
  function getExpiresIn(expiresAtStr: string, currentTimestamp: number): string {
    try {
      const expiresAt = new Date(expiresAtStr);
      const diffMs = expiresAt.getTime() - currentTimestamp;
      if (diffMs <= 0) return 'Expired';
      
      const diffSecs = Math.floor(diffMs / 1000);
      const diffMins = Math.floor(diffSecs / 60);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);

      if (diffDays > 0) {
        const remainingHours = diffHours % 24;
        return `${diffDays}d ${remainingHours}h`;
      }
      if (diffHours > 0) {
        const remainingMins = diffMins % 60;
        return `${diffHours}h ${remainingMins}m`;
      }
      if (diffMins > 0) {
        const remainingSecs = diffSecs % 60;
        return `${diffMins}m ${remainingSecs}s`;
      }
      return `${diffSecs}s`;
    } catch {
      return expiresAtStr;
    }
  }

  function formatTime(timestampStr: string): string {
    try {
      const date = new Date(timestampStr);
      const today = new Date();
      if (date.toDateString() === today.toDateString()) {
        return date.toLocaleTimeString();
      }
      return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
    } catch {
      return timestampStr;
    }
  }

  async function loadRecords() {
    dbLoading = true;
    try {
      const data = await fetchDbRecords({
        limit: dbLimit,
        offset: dbOffset,
        search: dbSearch,
        status: dbStatus,
        sort_by: dbSortBy,
        sort_order: dbSortOrder,
      });
      dbRecords = data.records || [];
      dbTotal = data.total || 0;
      dbError = null;
    } catch (e: any) {
      dbError = e.message || 'Failed to fetch database records';
      console.error(e);
    } finally {
      dbLoading = false;
    }
  }

  function handleDbSearch(e: Event) {
    e.preventDefault();
    dbOffset = 0;
    loadRecords();
  }

  function handleDbSort(column: string) {
    if (dbSortBy === column) {
      dbSortOrder = dbSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
      dbSortBy = column;
      dbSortOrder = 'desc';
    }
    dbOffset = 0;
    loadRecords();
  }

  function handleDbPageChange(newOffset: number) {
    dbOffset = newOffset;
    loadRecords();
  }

  function handleDbStatusChange() {
    dbOffset = 0;
    loadRecords();
  }

  onMount(() => {
    loadRecords();
    const countdownInterval = setInterval(() => {
      nowTime = Date.now();
    }, 1000);

    return () => {
      clearInterval(countdownInterval);
    };
  });
</script>

<div class="card db-records-card">
  <div class="db-records-header">
    <div class="db-title-area">
      <span class="card-icon">🗄️</span>
      <div>
        <h3>Database Entities</h3>
        <p class="card-description">View all IP reputation records stored in the SQLite database.</p>
      </div>
    </div>

    <div class="db-actions">
      <!-- Search form -->
      <form class="db-search-form" onsubmit={handleDbSearch}>
        <input 
          type="text" 
          placeholder="Search IP address..." 
          bind:value={dbSearch} 
          class="search-input"
        />
        <button type="submit" class="btn-search">Search</button>
        {#if dbSearch}
          <button 
            type="button" 
            class="btn-clear" 
            onclick={() => { dbSearch = ''; dbOffset = 0; loadRecords(); }}
          >
            Clear
          </button>
        {/if}
      </form>

      <!-- Status Filter -->
      <select 
        bind:value={dbStatus} 
        onchange={handleDbStatusChange}
        class="filter-select"
      >
        <option value="">All Statuses</option>
        <option value="threat">Threat</option>
        <option value="safe">Safe</option>
      </select>

      <button 
        type="button" 
        class="btn-refresh" 
        onclick={loadRecords} 
        disabled={dbLoading}
      >
        🔄 Refresh
      </button>
    </div>
  </div>

  <!-- Error/Loading/Empty states -->
  {#if dbError}
    <div class="error-alert">
      <span class="alert-icon">⚠️</span>
      <div class="alert-content">
        <h4>Failed to load database records</h4>
        <p>{dbError}</p>
      </div>
    </div>
  {:else if dbLoading && dbRecords.length === 0}
    <div class="loading-state">
      <div class="spinner"></div>
      <p>Loading database entities...</p>
    </div>
  {:else}
    {#if dbRecords.length === 0}
      <div class="empty-state">
        <span class="empty-icon">📭</span>
        <p>No database records found.</p>
      </div>
    {:else}
      <!-- Records Table -->
      <div class="table-container">
        <table class="db-table">
          <thead>
            <tr>
              <th onclick={() => handleDbSort('ip')} class="sortable">
                IP Address {dbSortBy === 'ip' ? (dbSortOrder === 'asc' ? '▲' : '▼') : ''}
              </th>
              <th onclick={() => handleDbSort('status')} class="sortable">
                Status {dbSortBy === 'status' ? (dbSortOrder === 'asc' ? '▲' : '▼') : ''}
              </th>
              <th onclick={() => handleDbSort('score')} class="sortable">
                Score {dbSortBy === 'score' ? (dbSortOrder === 'asc' ? '▲' : '▼') : ''}
              </th>
              <th onclick={() => handleDbSort('source')} class="sortable">
                Source {dbSortBy === 'source' ? (dbSortOrder === 'asc' ? '▲' : '▼') : ''}
              </th>
              <th onclick={() => handleDbSort('checked_at')} class="sortable">
                Last Checked {dbSortBy === 'checked_at' ? (dbSortOrder === 'asc' ? '▲' : '▼') : ''}
              </th>
              <th onclick={() => handleDbSort('expires_at')} class="sortable">
                TTL / Deletion Countdown {dbSortBy === 'expires_at' ? (dbSortOrder === 'asc' ? '▲' : '▼') : ''}
              </th>
            </tr>
          </thead>
          <tbody>
            {#each dbRecords as record}
              <tr class="status-row-{record.status}">
                <td class="font-mono font-bold">{record.ip}</td>
                <td>
                  <Badge 
                    type={record.status === 'allow' || record.status === 'safe' ? 'success' : record.status === 'threat' ? 'error' : 'warning'} 
                    text={record.status.toUpperCase()} 
                  />
                </td>
                <td class="font-mono">{record.score}%</td>
                <td>
                  <SourcePill source={record.source} />
                </td>
                <td class="text-sm text-secondary">{formatTime(record.checked_at)}</td>
                <td>
                  <div class="countdown-container">
                    <span class="countdown-timer font-mono text-cyan">
                      {getExpiresIn(record.expires_at, nowTime)}
                    </span>
                    <span class="countdown-timestamp text-xs text-muted">
                      ({formatTime(record.expires_at)})
                    </span>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <!-- Pagination controls -->
      <div class="pagination">
        <span class="pagination-info">
          Showing {dbOffset + 1} - {Math.min(dbOffset + dbLimit, dbTotal)} of {dbTotal} records
        </span>
        <div class="pagination-buttons">
          <button 
            type="button" 
            class="btn-page" 
            disabled={dbOffset === 0}
            onclick={() => handleDbPageChange(Math.max(0, dbOffset - dbLimit))}
          >
            ◀ Previous
          </button>
          <span class="page-num">
            Page {Math.floor(dbOffset / dbLimit) + 1} of {Math.ceil(dbTotal / dbLimit)}
          </span>
          <button 
            type="button" 
            class="btn-page" 
            disabled={dbOffset + dbLimit >= dbTotal}
            onclick={() => handleDbPageChange(dbOffset + dbLimit)}
          >
            Next ▶
          </button>
        </div>
      </div>
    {/if}
  {/if}
</div>

<style>
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: var(--card-shadow);
    backdrop-filter: var(--glass-blur);
    -webkit-backdrop-filter: var(--glass-blur);
    transition: transform 0.2s ease, border-color 0.2s ease;
    animation: glow 6s infinite ease-in-out;
  }

  .db-records-card {
    grid-column: 1 / -1;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .db-records-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.5rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 1rem;
  }

  .db-title-area {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .card-icon {
    font-size: 1.25rem;
  }

  .card-description {
    font-size: 0.875rem;
    color: var(--text-muted);
    line-height: 1.4;
    margin-top: 0.5rem;
  }

  .db-actions {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .db-search-form {
    display: flex;
    gap: 0.5rem;
  }

  .search-input {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 0.875rem;
    min-width: 240px;
    outline: none;
    transition: border-color 0.2s ease;
  }

  .search-input:focus {
    border-color: var(--accent-primary);
  }

  .btn-search {
    background: var(--accent-primary);
    color: var(--text-primary);
    border: none;
    padding: 0.5rem 1.25rem;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: background-color 0.2s ease;
  }

  .btn-search:hover {
    background: #7c3aed;
  }

  .btn-clear {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-clear:hover {
    color: var(--text-primary);
    border-color: rgba(255, 255, 255, 0.2);
  }

  .filter-select {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    padding: 0.5rem 2rem 0.5rem 1rem;
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 0.875rem;
    cursor: pointer;
    outline: none;
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
    background-repeat: no-repeat;
    background-position: right 0.75rem center;
    background-size: 1rem;
  }

  .btn-refresh {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 0.5rem 1.25rem;
    border-radius: 8px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-refresh:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.08);
  }

  .btn-refresh:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .table-container {
    overflow-x: auto;
    border: 1px solid var(--border-color);
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.01);
  }

  .db-table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    font-size: 0.9rem;
  }

  .db-table th, .db-table td {
    padding: 1rem 1.25rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .db-table th {
    background: rgba(255, 255, 255, 0.02);
    font-weight: 500;
    color: var(--text-secondary);
    user-select: none;
  }

  .db-table th.sortable {
    cursor: pointer;
  }

  .db-table th.sortable:hover {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.04);
  }

  .db-table tbody tr {
    transition: background-color 0.15s ease;
  }

  .db-table tbody tr:hover {
    background: rgba(255, 255, 255, 0.015);
  }

  .db-table tbody tr.status-row-threat:hover {
    background: rgba(239, 68, 68, 0.02);
  }

  .font-mono {
    font-family: monospace;
  }

  .font-bold {
    font-weight: 600;
  }

  .text-sm {
    font-size: 0.8rem;
  }

  .text-xs {
    font-size: 0.75rem;
  }

  .text-secondary {
    color: var(--text-secondary);
  }

  .text-muted {
    color: var(--text-muted);
  }

  .countdown-container {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .countdown-timer {
    font-weight: 500;
  }

  .pagination {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-top: 1rem;
    flex-wrap: wrap;
    gap: 1rem;
  }

  .pagination-info {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .pagination-buttons {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .btn-page {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-size: 0.875rem;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-page:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.08);
  }

  .btn-page:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .page-num {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .error-alert {
    background: rgba(239, 68, 68, 0.07);
    border: 1px solid rgba(239, 68, 68, 0.20);
    padding: 1.25rem 1.5rem;
    border-radius: 12px;
    display: flex;
    gap: 1rem;
    align-items: flex-start;
  }

  .error-alert h4 {
    color: var(--color-error);
    margin-bottom: 0.25rem;
  }

  .error-alert p {
    color: var(--text-secondary);
    font-size: 0.875rem;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 4rem 2rem;
    border: 1px dashed var(--border-color);
    border-radius: 12px;
  }

  .empty-icon {
    font-size: 2rem;
  }

  .text-cyan { color: var(--accent-cyan); }

  .loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    padding: 4rem;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid rgba(139, 92, 246, 0.1);
    border-top: 3px solid var(--accent-primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
</style>
