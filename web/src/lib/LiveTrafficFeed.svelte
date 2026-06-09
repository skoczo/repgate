<script lang="ts">
  import { onMount } from 'svelte';
  import { slide } from 'svelte/transition';
  import { fetchEvents, type RepgateEvent, type SystemStatus } from './api';
  import Badge from './Badge.svelte';
  import SourcePill from './SourcePill.svelte';

  let { status } = $props<{
    status: SystemStatus;
  }>();

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
      const data = await fetchEvents(50, null, eventFilter);
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
      const data = await fetchEvents(50, oldestEventId, eventFilter);
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

  onMount(() => {
    if (status && !status.live_stream_disabled) {
      fetchInitialEvents();
      connectSSE();
    }

    return () => {
      if (sseSource) {
        sseSource.close();
      }
    };
  });
</script>

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
              <Badge 
                type={event.action === 'allow' ? 'success' : event.action === 'block' ? 'error' : 'warning'} 
                text={event.action.toUpperCase()} 
              />
              <SourcePill source={event.source} />
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

  .card-icon {
    font-size: 1.25rem;
  }

  .card-description {
    font-size: 0.875rem;
    color: var(--text-muted);
    line-height: 1.4;
    margin-top: 0.5rem;
  }

  .retention-info {
    font-size: 0.875rem;
    color: var(--text-muted);
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
    font-size: 0.875rem;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .disabled-feed-banner {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 0.5rem;
    padding: 3rem 2rem;
    background: rgba(255, 255, 255, 0.01);
    border: 1px dashed var(--border-color);
    border-radius: 12px;
  }

  .banner-icon {
    font-size: 1.75rem;
  }

  .banner-hint {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-top: 0.5rem;
  }

  .empty-feed {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 4rem 2rem;
    color: var(--text-secondary);
  }

  .feed-loader {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 1rem;
    color: var(--text-muted);
    font-size: 0.875rem;
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
</style>
