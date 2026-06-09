<script lang="ts">
  let { errorMsg } = $props<{
    errorMsg: string | null;
  }>();
</script>

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

<style>
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
</style>
