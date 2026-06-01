<script lang="ts">
  import { onMount } from 'svelte';

  interface SystemStatus {
    uptime: string;
    fail_open: boolean;
    l1_cache_entries: number;
    l1_cache_capacity: number;
    l2_cache_entries: number;
    l2_threat_entries: number;
  }

  let status = $state<SystemStatus | null>(null);
  let errorMsg = $state<string | null>(null);
  let loading = $state<boolean>(true);
  let lastUpdated = $state<string>('');

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

  onMount(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  });
</script>

<main class="dashboard">
  <!-- Header Section -->
  <header class="header">
    <div class="brand">
      <div class="logo-shield">🛡️</div>
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

  .logo-shield {
    font-size: 2.5rem;
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
</style>
