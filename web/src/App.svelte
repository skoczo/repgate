<script lang="ts">
  import { onMount } from 'svelte';
  import { fetchStatus, type SystemStatus } from './lib/api';
  import Header from './lib/Header.svelte';
  import DashboardTab from './lib/DashboardTab.svelte';
  import DatabaseTab from './lib/DatabaseTab.svelte';
  import LiveTrafficFeed from './lib/LiveTrafficFeed.svelte';

  let activeTab = $state<'dashboard' | 'database'>('dashboard');
  let status = $state<SystemStatus | null>(null);
  let errorMsg = $state<string | null>(null);
  let loading = $state<boolean>(true);
  let lastUpdated = $state<string>('');

  async function updateStatus() {
    try {
      status = await fetchStatus();
      errorMsg = null;
      lastUpdated = new Date().toLocaleTimeString();
    } catch (e: any) {
      errorMsg = e.message || 'Failed to connect to backend service';
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    updateStatus();
    const interval = setInterval(updateStatus, 5000);

    return () => {
      clearInterval(interval);
    };
  });
</script>

<main class="dashboard">
  <!-- Header Section -->
  <Header {errorMsg} />

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
        onclick={() => activeTab = 'database'}
      >
        🗄️ Database Cache
      </button>
    </div>

    {#if activeTab === 'dashboard'}
      <DashboardTab {status} />
      <LiveTrafficFeed {status} />
    {/if}

    {#if activeTab === 'database'}
      <DatabaseTab />
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

  /* Navigation Tabs */
  .tabs-nav {
    display: flex;
    gap: 1rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.5rem;
  }

  .tab-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 0.5rem 1rem;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.2s ease;
  }

  .tab-btn:hover {
    color: var(--text-primary);
  }

  .tab-btn.active {
    color: var(--accent-primary);
    border-bottom-color: var(--accent-primary);
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

  .font-mono {
    font-family: monospace;
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
