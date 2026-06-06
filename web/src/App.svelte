<script lang="ts">
  import { onMount } from 'svelte';
  import { slide } from 'svelte/transition';

  interface SystemStatus {
    uptime: string;
    fail_open: boolean;
    l1_cache_entries: number;
    l1_cache_capacity: number;
    l2_cache_entries: number;
    l2_threat_entries: number;
  }

  interface RepgateEvent {
    id: number;
    ip: string;
    target_host: string;
    target_path: string;
    action: string;
    source: string;
    timestamp: string;
  }

  let activeTab = $state<'dashboard' | 'database'>('dashboard');
  let status = $state<SystemStatus | null>(null);
  let errorMsg = $state<string | null>(null);
  let loading = $state<boolean>(true);
  let lastUpdated = $state<string>('');

  // Live stream and event history state
  let events = $state<RepgateEvent[]>([]);
  let eventFilter = $state<string>('all');
  let liveConnected = $state<boolean>(false);
  let loadingInitial = $state<boolean>(true);
  let loadingMore = $state<boolean>(false);
  let hasMoreEvents = $state<boolean>(true);
  let oldestEventId = $state<number | null>(null);
  let sseSource = $state<EventSource | null>(null);

  let filteredEvents = $derived(
    events.filter(e => {
      if (eventFilter === 'all') return true;
      return e.action === eventFilter;
    })
  );

  async function fetchStatus() {
    try {
      const res = await fetch('/api/v1/status');
      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }
      status = await res.json();
      errorMsg = null;
      lastUpdated = new Date().toLocaleTimeString();
    } catch (e: any) {
      errorMsg = e.message || 'Failed to connect to backend service';
    } finally {
      loading = false;
    }
  }

  function setFilter(filter: string) {
    if (eventFilter === filter) return;
    eventFilter = filter;
    events = [];
    hasMoreEvents = true;
    oldestEventId = null;
    loadingInitial = true;
    fetchInitialEvents();
  }

  async function fetchInitialEvents() {
    try {
      const filterParam = eventFilter !== 'all' ? `&action=${eventFilter}` : '';
      const res = await fetch(`/api/v1/events?limit=50${filterParam}`);
      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }
      const data = await res.json();
      events = data;
      if (data.length < 50) {
        hasMoreEvents = false;
      }
      if (data.length > 0) {
        oldestEventId = data[data.length - 1].id;
      } else {
        oldestEventId = null;
      }
    } catch (e: any) {
      console.error('Failed to load initial events', e);
    } finally {
      loadingInitial = false;
    }
  }

  async function loadMoreEvents() {
    if (loadingMore || !hasMoreEvents || oldestEventId === null) {
      return;
    }
    loadingMore = true;
    try {
      const filterParam = eventFilter !== 'all' ? `&action=${eventFilter}` : '';
      const res = await fetch(`/api/v1/events?before_id=${oldestEventId}&limit=50${filterParam}`);
      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }
      const data = await res.json();
      if (data.length === 0) {
        hasMoreEvents = false;
      } else {
        events = [...events, ...data];
        oldestEventId = data[data.length - 1].id;
        if (data.length < 50) {
          hasMoreEvents = false;
        }
      }
    } catch (e: any) {
      console.error('Failed to load more events', e);
    } finally {
      loadingMore = false;
    }
  }

  function handleScroll(e: Event) {
    const target = e.currentTarget as HTMLDivElement;
    if (target.scrollHeight - target.scrollTop - target.clientHeight < 50) {
      loadMoreEvents();
    }
  }

  function connectSSE() {
    if (sseSource) {
      sseSource.close();
    }

    const source = new EventSource('/api/v1/stream/logs');
    sseSource = source;

    source.onopen = () => {
      liveConnected = true;
    };

    source.onerror = () => {
      liveConnected = false;
      setTimeout(connectSSE, 5000);
    };

    source.onmessage = (event) => {
      try {
        const newEvent = JSON.parse(event.data) as RepgateEvent;
        if (!events.some(e => e.id === newEvent.id)) {
          events = [newEvent, ...events];
        }
      } catch (err) {
        console.error('Failed to parse SSE event data', err);
      }
    };
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

  // Database Tab State
  interface DbRecordsResponse {
    records: IPRecord[];
    total: number;
  }

  interface IPRecord {
    ip: string;
    status: string;
    score: number;
    source: string;
    checked_at: string;
    expires_at: string;
  }

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

  async function fetchDbRecords() {
    dbLoading = true;
    try {
      const queryParams = new URLSearchParams({
        limit: dbLimit.toString(),
        offset: dbOffset.toString(),
        search: dbSearch,
        status: dbStatus,
        sort_by: dbSortBy,
        sort_order: dbSortOrder,
      });
      const res = await fetch(`/api/v1/db/records?${queryParams.toString()}`);
      if (!res.ok) {
        throw new Error(`HTTP error! Status: ${res.status}`);
      }
      const data = await res.json() as DbRecordsResponse;
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
    fetchDbRecords();
  }

  function handleDbSort(column: string) {
    if (dbSortBy === column) {
      dbSortOrder = dbSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
      dbSortBy = column;
      dbSortOrder = 'desc';
    }
    dbOffset = 0;
    fetchDbRecords();
  }

  function handleDbPageChange(newOffset: number) {
    dbOffset = newOffset;
    fetchDbRecords();
  }

  function handleDbStatusChange() {
    dbOffset = 0;
    fetchDbRecords();
  }

  onMount(() => {
    fetchStatus();
    fetchInitialEvents();
    connectSSE();

    const interval = setInterval(fetchStatus, 5000);
    const countdownInterval = setInterval(() => {
      nowTime = Date.now();
    }, 1000);

    return () => {
      clearInterval(interval);
      clearInterval(countdownInterval);
      if (sseSource) {
        sseSource.close();
      }
    };
  });
</script>

<main class="dashboard">
  <!-- Header Section -->
  <header class="header">
    <div class="brand">
      <img src="/logo.png" alt="Repgate Logo" class="logo-image" />
      <div>
        <h1>REPGATE</h1>
        <p class="subtitle">IP Reputation & Threat Filter Gateway</p>
      </div>
    </div>
    
    <div class="connection-status">
      {#if errorMsg}
        <span class="status-indicator error-pulse"></span>
        <span class="status-text text-error">Disconnected</span>
      {:else}
        <span class="status-indicator success-pulse"></span>
        <span class="status-text text-success">Gateway Connected</span>
      {/if}
    </div>
  </header>

  <!-- Error Alerts -->
  {#if errorMsg}
    <div class="alert-box">
      <div class="alert-title">⚠️ Connection Interrupted</div>
      <p>{errorMsg}. Checking endpoint at /api/v1/status...</p>
    </div>
  {/if}

  <!-- Loading State -->
  {#if loading && !status}
    <div class="loading-state">
      <div class="spinner"></div>
      <p>Initializing security dashboard...</p>
    </div>
  {:else if status}
    <!-- Navigation Tabs -->
    <div class="tabs-nav">
      <button 
        type="button" 
        class="tab-btn" 
        class:active={activeTab === 'dashboard'} 
        onclick={() => activeTab = 'dashboard'}
      >
        📊 Dashboard
      </button>
      <button 
        type="button" 
        class="tab-btn" 
        class:active={activeTab === 'database'} 
        onclick={() => { activeTab = 'database'; fetchDbRecords(); }}
      >
        🗄️ Database Cache
      </button>
    </div>

    {#if activeTab === 'dashboard'}
      <!-- Grid Layout -->
      <div class="grid">
      
      <!-- Card 1: System Health -->
      <div class="card health-card">
        <div class="card-header">
          <span class="card-icon">⚡</span>
          <h3>System Health</h3>
        </div>
        <div class="card-body">
          <div class="metric-group">
            <span class="metric-label">Gateway Status</span>
            <span class="metric-value text-success">ONLINE</span>
          </div>
          <div class="metric-group">
            <span class="metric-label">Uptime</span>
            <span class="metric-value font-mono">{status.uptime}</span>
          </div>
          <div class="metric-group">
            <span class="metric-label">Fail-Open Mode</span>
            {#if status.fail_open}
              <span class="badge badge-success">Enabled</span>
            {:else}
              <span class="badge badge-warning">Disabled (Fail-Closed)</span>
            {/if}
          </div>
        </div>
      </div>

      <!-- Card 2: L1 Memory Cache -->
      <div class="card cache-card">
        <div class="card-header">
          <span class="card-icon">🧠</span>
          <h3>L1 Cache (In-Memory)</h3>
        </div>
        <div class="card-body">
          <div class="progress-container">
            <div class="progress-text">
              <span class="metric-label">LRU Cache Utilization</span>
              <span class="metric-value font-mono">
                {status.l1_cache_entries} / {status.l1_cache_capacity}
              </span>
            </div>
            <div class="progress-bar-bg">
              <div 
                class="progress-bar-fill fill-cyan" 
                style="width: {(status.l1_cache_entries / (status.l1_cache_capacity || 1)) * 100}%"
              ></div>
            </div>
          </div>
          <p class="card-description">
            High-performance in-memory cache prioritizing instant response times for recurring traffic.
          </p>
        </div>
      </div>

      <!-- Card 3: L2 Database Cache -->
      <div class="card db-card">
        <div class="card-header">
          <span class="card-icon">🗄️</span>
          <h3>L2 Cache (SQLite DB)</h3>
        </div>
        <div class="card-body">
          <div class="metric-row">
            <div class="metric-sub-card">
              <span class="metric-label">Total Cache Records</span>
              <span class="metric-value font-mono text-cyan">{status.l2_cache_entries}</span>
            </div>
            <div class="metric-sub-card border-error">
              <span class="metric-label">Active Threats Blocked</span>
              <span class="metric-value font-mono text-error">{status.l2_threat_entries}</span>
            </div>
          </div>
          <p class="card-description">
            Persistent local database cache used to preserve IP evaluations across service restarts.
          </p>
        </div>
      </div>

    </div>

    <!-- Live Traffic Feed Card -->
    <div class="card feed-card">
      <div class="feed-header">
        <div class="feed-title-area">
          <span class="card-icon">📡</span>
          <div>
            <h3>Live Traffic Feed</h3>
            <p class="card-description">
              Real-time analysis stream of gateway checks and threat responses.
              {#if status && !status.live_stream_disabled}
                <span class="retention-info">
                  (Retention: {status.live_stream_retention_days === -1 ? 'Infinite' : `${status.live_stream_retention_days} days`})
                </span>
              {/if}
            </p>
          </div>
        </div>
        
        <div class="feed-controls">
          <div class="filters">
            <button 
              type="button"
              class="btn-filter" 
              class:active={eventFilter === 'all'} 
              onclick={() => setFilter('all')}
              disabled={status?.live_stream_disabled}
            >
              All
            </button>
            <button 
              type="button"
              class="btn-filter filter-allow" 
              class:active={eventFilter === 'allow'} 
              onclick={() => setFilter('allow')}
              disabled={status?.live_stream_disabled}
            >
              Allowed
            </button>
            <button 
              type="button"
              class="btn-filter filter-block" 
              class:active={eventFilter === 'block'} 
              onclick={() => setFilter('block')}
              disabled={status?.live_stream_disabled}
            >
              Blocked
            </button>
          </div>

          <div class="live-status" class:connected={liveConnected} class:disabled={status?.live_stream_disabled}>
            <span class="beacon"></span>
            <span class="status-label">
              {#if status?.live_stream_disabled}
                DISABLED
              {:else}
                {liveConnected ? 'LIVE' : 'RECONNECTING...'}
              {/if}
            </span>
          </div>
        </div>
      </div>

      <div class="feed-container" onscroll={handleScroll}>
        {#if status?.live_stream_disabled}
          <div class="disabled-feed-banner">
            <span class="banner-icon">⚠️</span>
            <h4>Livestream is Disabled</h4>
            <p>
              The real-time traffic feed and event logs are disabled because <code>live_stream_retention_days</code> is set to <code>0</code> in the configuration.
            </p>
            <p class="banner-hint">
              To enable this feature, set <code>live_stream_retention_days</code> to <code>-1</code> (for infinite retention) or to a positive number of days (e.g., <code>7</code>) in your <code>config.yaml</code>.
            </p>
          </div>
        {:else if filteredEvents.length === 0}
          <div class="empty-feed">
            {#if loadingInitial}
              <div class="spinner-small"></div>
              <p>Loading event history...</p>
            {:else}
              <p>No events matching the filter found.</p>
            {/if}
          </div>
        {:else}
          <div class="feed-list">
            {#each filteredEvents as event (event.id)}
              <div transition:slide={{ duration: 200 }} class="event-row action-{event.action}">
                <div class="event-meta">
                  <span class="event-time">{formatTime(event.timestamp)}</span>
                  <span class="event-ip">{event.ip}</span>
                </div>
                
                <div class="event-badge-group">
                  <span class="badge badge-{event.action === 'allow' ? 'success' : event.action === 'block' ? 'error' : 'warning'}">
                    {event.action.toUpperCase()}
                  </span>
                  
                  <span class="source-pill source-{event.source.toLowerCase().replace(' (failopen)', '-failopen').replace(/\s+/g, '-')}">
                    {event.source}
                  </span>
                </div>

                <div class="event-details">
                  <span class="event-host">{event.target_host}</span>
                  <span class="event-path" title={event.target_path}>{event.target_path}</span>
                </div>
              </div>
            {/each}
            
            {#if loadingMore}
              <div class="feed-loader">
                <div class="spinner-small"></div>
                <p>Loading older events...</p>
              </div>
            {:else}
              <div class="scroll-bottom-spacer"></div>
            {/if}
          </div>
        {/if}
      </div>
    </div>
    {/if}

    {#if activeTab === 'database'}
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
                  onclick={() => { dbSearch = ''; dbOffset = 0; fetchDbRecords(); }}
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
              onclick={fetchDbRecords} 
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
                        <span class="badge badge-{record.status === 'allow' || record.status === 'safe' ? 'success' : record.status === 'threat' ? 'error' : 'warning'}">
                          {record.status.toUpperCase()}
                        </span>
                      </td>
                      <td class="font-mono">{record.score}%</td>
                      <td>
                        <span class="source-pill source-{record.source.toLowerCase().replace(/\s+/g, '-')}">
                          {record.source}
                        </span>
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
    {/if}
  {/if}

  <!-- Footer Info -->
  <footer class="footer">
    {#if lastUpdated}
      <p>Dashboard updates automatically. Last sync: <span class="font-mono">{lastUpdated}</span></p>
    {/if}
  </footer>
</main>

<style>
  .dashboard {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  /* Header Styles */
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 1.5rem;
    border-bottom: 1px solid var(--border-color);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .logo-image {
    height: 80px;
    width: auto;
    filter: drop-shadow(0 0 8px rgba(139, 92, 246, 0.4));
  }

  .subtitle {
    font-size: 0.875rem;
    color: var(--text-secondary);
    margin-top: 0.15rem;
  }

  .connection-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(255, 255, 255, 0.03);
    padding: 0.5rem 1rem;
    border-radius: 9999px;
    border: 1px solid var(--border-color);
  }

  .status-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }

  .success-pulse {
    background-color: var(--color-success);
    animation: pulse 2s infinite;
  }

  .error-pulse {
    background-color: var(--color-error);
    animation: pulse 1.5s infinite;
  }

  .status-text {
    font-size: 0.875rem;
    font-weight: 500;
  }

  .text-success { color: var(--color-success); }
  .text-error { color: var(--color-error); }
  .text-cyan { color: var(--accent-cyan); }

  /* Error Alert */
  .alert-box {
    background: rgba(239, 68, 68, 0.07);
    border: 1px solid rgba(239, 68, 68, 0.2);
    border-radius: 12px;
    padding: 1rem 1.5rem;
  }

  .alert-title {
    font-weight: 600;
    color: var(--color-error);
    margin-bottom: 0.25rem;
  }

  /* Grid & Cards */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 1.5rem;
  }

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

  .card:hover {
    transform: translateY(-2px);
    border-color: rgba(139, 92, 246, 0.3);
  }

  .card-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 0.75rem;
  }

  .card-icon {
    font-size: 1.25rem;
  }

  .card-body {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .card-description {
    font-size: 0.875rem;
    color: var(--text-muted);
    line-height: 1.4;
    margin-top: 0.5rem;
  }

  /* Metric Layouts */
  .metric-group {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.25rem 0;
  }

  .metric-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  .metric-value {
    font-weight: 600;
  }

  .font-mono {
    font-family: monospace;
  }

  .badge {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
  }

  .badge-success {
    background: rgba(16, 185, 129, 0.1);
    color: var(--color-success);
    border: 1px solid rgba(16, 185, 129, 0.25);
  }

  .badge-warning {
    background: rgba(245, 158, 11, 0.1);
    color: var(--color-warning);
    border: 1px solid rgba(245, 158, 11, 0.25);
  }

  /* Progress Bar */
  .progress-container {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .progress-text {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .progress-bar-bg {
    height: 8px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 9999px;
    overflow: hidden;
  }

  .progress-bar-fill {
    height: 100%;
    border-radius: 9999px;
    transition: width 0.4s cubic-bezier(0.4, 0, 0.2, 1);
  }

  .fill-cyan {
    background: linear-gradient(90deg, var(--accent-primary) 0%, var(--accent-cyan) 100%);
  }

  /* DB Metric Cards */
  .metric-row {
    display: flex;
    gap: 1rem;
  }

  .metric-sub-card {
    flex: 1;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.05);
    padding: 0.75rem;
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .metric-sub-card.border-error {
    border-color: rgba(239, 68, 68, 0.15);
  }

  .metric-sub-card .metric-label {
    font-size: 0.75rem;
  }

  .metric-sub-card .metric-value {
    font-size: 1.5rem;
  }

  /* Loading State */
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

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  /* Footer */
  .footer {
    text-align: center;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-color);
  }

  .footer p {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  /* Feed Card and Layout */
  .feed-card {
    grid-column: 1 / -1;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .feed-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 1rem;
  }

  .feed-title-area {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .feed-controls {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .filters {
    display: flex;
    background: rgba(255, 255, 255, 0.03);
    padding: 0.25rem;
    border-radius: 8px;
    border: 1px solid var(--border-color);
  }

  .btn-filter {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 0.35rem 0.85rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-filter:hover {
    color: var(--text-primary);
  }

  .btn-filter.active {
    background: var(--accent-primary);
    color: var(--text-primary);
    box-shadow: 0 2px 8px rgba(139, 92, 246, 0.4);
  }

  .btn-filter.filter-allow.active {
    background: var(--color-success);
    box-shadow: 0 2px 8px rgba(16, 185, 129, 0.4);
  }

  .btn-filter.filter-block.active {
    background: var(--color-error);
    box-shadow: 0 2px 8px rgba(239, 68, 68, 0.4);
  }

  /* Live Status Indicator */
  .live-status {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    background: rgba(239, 68, 68, 0.05);
    border: 1px solid rgba(239, 68, 68, 0.15);
    padding: 0.35rem 0.75rem;
    border-radius: 8px;
    transition: all 0.3s ease;
  }

  .live-status.connected {
    background: rgba(16, 185, 129, 0.05);
    border-color: rgba(16, 185, 129, 0.15);
  }

  .live-status .beacon {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: var(--color-error);
  }

  .live-status.connected .beacon {
    background-color: var(--color-success);
    animation: pulse 2s infinite;
  }

  .status-label {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    color: var(--color-error);
  }

  .live-status.connected .status-label {
    color: var(--color-success);
  }

  /* Feed Container & Scrolling */
  .feed-container {
    max-height: 480px;
    overflow-y: auto;
    padding-right: 0.25rem;
  }

  .feed-container::-webkit-scrollbar {
    width: 6px;
  }

  .feed-container::-webkit-scrollbar-track {
    background: transparent;
  }

  .feed-container::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 999px;
  }

  .feed-container::-webkit-scrollbar-thumb:hover {
    background: rgba(255, 255, 255, 0.25);
  }

  .feed-list {
    display: flex;
    flex-direction: column;
  }

  /* Event Row Styling */
  .event-row {
    display: grid;
    grid-template-columns: 260px 180px 1fr;
    align-items: center;
    gap: 1.5rem;
    padding: 0.85rem 1.25rem;
    background: rgba(255, 255, 255, 0.015);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    margin-bottom: 0.65rem;
    transition: background-color 0.2s ease, transform 0.15s ease;
  }

  .event-row:hover {
    background: rgba(255, 255, 255, 0.035);
    transform: translateX(2px);
  }

  .event-row.action-allow {
    border-left: 4px solid var(--color-success);
  }

  .event-row.action-block {
    border-left: 4px solid var(--color-error);
  }

  .event-row.action-tarpit {
    border-left: 4px solid var(--color-warning);
  }

  .event-meta {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.25rem;
  }

  .event-time {
    font-size: 0.75rem;
    color: var(--text-muted);
    font-family: monospace;
    white-space: nowrap;
  }

  .event-ip {
    font-size: 0.9rem;
    font-weight: 600;
    font-family: monospace;
    color: var(--text-primary);
  }

  .event-badge-group {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .badge-error {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-error);
    border: 1px solid rgba(239, 68, 68, 0.25);
  }

  .source-pill {
    font-size: 0.75rem;
    font-weight: 500;
    padding: 0.15rem 0.5rem;
    border-radius: 6px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
  }

  .source-pill.source-abuseipdb {
    background: rgba(6, 182, 212, 0.08);
    color: var(--accent-cyan);
    border-color: rgba(6, 182, 212, 0.15);
  }

  .source-pill.source-activedefence {
    background: rgba(236, 72, 153, 0.08);
    color: var(--accent-pink);
    border-color: rgba(236, 72, 153, 0.15);
  }

  .source-pill.source-system {
    background: rgba(139, 92, 246, 0.08);
    color: var(--accent-primary);
    border-color: rgba(139, 92, 246, 0.15);
  }

  .source-pill.source-abuseipdb-failopen,
  .source-pill.source-system-failopen {
    background: rgba(245, 158, 11, 0.08);
    color: var(--color-warning);
    border-color: rgba(245, 158, 11, 0.15);
  }

  .event-details {
    display: flex;
    align-items: center;
    gap: 1rem;
    min-width: 0;
  }

  .event-host {
    font-size: 0.8rem;
    color: var(--text-muted);
    font-family: monospace;
    white-space: nowrap;
  }

  .event-path {
    font-size: 0.85rem;
    color: var(--text-secondary);
    font-family: monospace;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }

  .empty-feed {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    padding: 4rem;
    color: var(--text-muted);
  }

  .feed-loader {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    padding: 1.5rem;
    color: var(--text-muted);
  }

  .spinner-small {
    width: 20px;
    height: 20px;
    border: 2px solid rgba(139, 92, 246, 0.1);
    border-top: 2px solid var(--accent-primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }

  .scroll-bottom-spacer {
    height: 10px;
  }

  @media (max-width: 768px) {
    .event-row {
      grid-template-columns: 1fr;
      gap: 0.5rem;
      align-items: flex-start;
    }
    
    .event-details {
      flex-direction: column;
      align-items: flex-start;
      gap: 0.25rem;
    }
  }

  /* Disabled Feed Banner & Retention Styling */
  .retention-info {
    color: var(--accent-cyan);
    font-size: 0.8rem;
    font-weight: 500;
    margin-left: 0.5rem;
  }

  .disabled-feed-banner {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    padding: 3rem 2rem;
    text-align: center;
    background: rgba(245, 158, 11, 0.02);
    border: 1px dashed rgba(245, 158, 11, 0.20);
    border-radius: 12px;
    color: var(--text-secondary);
  }

  .disabled-feed-banner h4 {
    color: var(--color-warning);
    font-size: 1.1rem;
    font-weight: 600;
    margin: 0;
  }

  .disabled-feed-banner code {
    background: rgba(255, 255, 255, 0.05);
    padding: 0.15rem 0.35rem;
    border-radius: 4px;
    font-family: monospace;
    color: var(--accent-pink);
  }

  .banner-icon {
    font-size: 2rem;
  }

  .banner-hint {
    font-size: 0.85rem;
    color: var(--text-muted);
    max-width: 500px;
    margin: 0;
  }

  .live-status.disabled {
    background: rgba(255, 255, 255, 0.03);
    border-color: var(--border-color);
  }

  .live-status.disabled .beacon {
    background-color: var(--text-muted);
    animation: none;
  }

  .live-status.disabled .status-label {
    color: var(--text-secondary);
  }

  /* Tabs Navigation Styles */
  .tabs-nav {
    display: flex;
    gap: 1rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1rem;
    margin-bottom: 0.5rem;
  }

  .tab-btn {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .tab-btn:hover {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.05);
    border-color: rgba(139, 92, 246, 0.3);
  }

  .tab-btn.active {
    background: var(--accent-primary);
    color: var(--text-primary);
    border-color: var(--accent-primary);
    box-shadow: 0 4px 12px rgba(139, 92, 246, 0.3);
  }

  /* Database Records Card and Header */
  .db-records-card {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    width: 100%;
  }

  .db-records-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.5rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    padding-bottom: 1.25rem;
  }

  .db-title-area {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .db-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }

  /* Search Form */
  .db-search-form {
    display: flex;
    align-items: center;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 0.25rem;
  }

  .search-input {
    background: transparent;
    border: none;
    outline: none;
    color: var(--text-primary);
    padding: 0.5rem 0.75rem;
    font-size: 0.9rem;
    width: 220px;
    font-family: inherit;
  }

  .search-input::placeholder {
    color: var(--text-muted);
  }

  .btn-search {
    background: var(--accent-primary);
    color: var(--text-primary);
    border: none;
    padding: 0.45rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.2s ease;
  }

  .btn-search:hover {
    background: #7c3aed;
  }

  .btn-clear {
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 0.5rem;
    cursor: pointer;
    font-size: 0.8rem;
    transition: color 0.2s ease;
  }

  .btn-clear:hover {
    color: var(--color-error);
  }

  .btn-refresh {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 0.65rem 1rem;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-refresh:hover {
    background: rgba(255, 255, 255, 0.08);
    border-color: rgba(255, 255, 255, 0.15);
  }

  /* Table Styles */
  .table-container {
    width: 100%;
    overflow-x: auto;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    background: rgba(255, 255, 255, 0.005);
  }

  .db-table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    font-size: 0.925rem;
  }

  .db-table th {
    background: rgba(255, 255, 255, 0.02);
    color: var(--text-secondary);
    font-weight: 600;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    user-select: none;
  }

  .db-table th.sortable {
    cursor: pointer;
    transition: color 0.2s ease, background-color 0.2s ease;
  }

  .db-table th.sortable:hover {
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.04);
  }

  .db-table td {
    padding: 1rem 1.25rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    vertical-align: middle;
  }

  .db-table tbody tr {
    transition: background-color 0.15s ease;
  }

  .db-table tbody tr:hover {
    background: rgba(255, 255, 255, 0.015);
  }

  .db-table tbody tr.status-row-threat:hover {
    background: rgba(239, 68, 68, 0.015);
  }

  .font-bold {
    font-weight: 600;
  }

  .text-sm {
    font-size: 0.85rem;
  }

  /* Countdown & TTL Cell */
  .countdown-container {
    display: flex;
    flex-direction: column;
    gap: 0.15rem;
  }

  .countdown-timer {
    font-weight: 600;
    color: var(--accent-cyan);
    font-size: 0.95rem;
  }

  .countdown-timestamp {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  /* Pagination */
  .pagination {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-top: 1rem;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
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
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 0.5rem 1rem;
    border-radius: 6px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-page:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.08);
    border-color: rgba(255, 255, 255, 0.15);
  }

  .btn-page:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .page-num {
    font-size: 0.875rem;
    color: var(--text-secondary);
  }

  /* General alerts */
  .error-alert {
    display: flex;
    gap: 1rem;
    background: rgba(239, 68, 68, 0.07);
    border: 1px solid rgba(239, 68, 68, 0.20);
    padding: 1.25rem 1.5rem;
    border-radius: 12px;
    color: var(--text-secondary);
  }

  .error-alert h4 {
    color: var(--color-error);
    font-size: 1rem;
    font-weight: 600;
    margin-bottom: 0.25rem;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 0.75rem;
    padding: 4rem 2rem;
    color: var(--text-secondary);
    background: rgba(255, 255, 255, 0.005);
    border: 1px dashed var(--border-color);
    border-radius: 12px;
  }

  .empty-icon {
    font-size: 2.5rem;
  }

  .filter-select {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    font-size: 0.9rem;
    cursor: pointer;
    font-family: inherit;
    outline: none;
    transition: all 0.2s ease;
  }

  .filter-select:hover {
    background: rgba(255, 255, 255, 0.06);
    border-color: rgba(255, 255, 255, 0.15);
  }

  .filter-select option {
    background: #0f0c1b;
    color: var(--text-primary);
  }
</style>
