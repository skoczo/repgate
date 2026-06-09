<script lang="ts">
  let { source } = $props<{
    source: string;
  }>();

  let formattedSourceClass = $derived(
    source.toLowerCase().replace(' (failopen)', '-failopen').replace(/\s+/g, '-')
  );
</script>

<span class="source-pill source-{formattedSourceClass}">
  {source}
</span>

<style>
  .source-pill {
    font-size: 0.75rem;
    font-weight: 500;
    padding: 0.15rem 0.5rem;
    border-radius: 6px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    display: inline-block;
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
</style>
