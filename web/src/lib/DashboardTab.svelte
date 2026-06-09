<script lang="ts">
  import type { SystemStatus } from './api';
  import Badge from './Badge.svelte';

  let { status } = $props<{
    status: SystemStatus;
  }>();
</script>

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
          <Badge type="success" text="Enabled" />
        {:else}
          <Badge type="warning" text="Disabled (Fail-Closed)" />
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

<style>
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

  .text-success { color: var(--color-success); }
  .text-error { color: var(--color-error); }
  .text-cyan { color: var(--accent-cyan); }
</style>
