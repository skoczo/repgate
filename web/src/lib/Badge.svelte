<script lang="ts">
  let { type, text } = $props<{
    type: 'success' | 'warning' | 'error';
    text: string;
  }>();
</script>

<span class="badge badge-{type}">
  {text}
</span>

<style>
  .badge {
    font-size: 0.75rem;
    font-weight: 600;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    display: inline-block;
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

  .badge-error {
    background: rgba(239, 68, 68, 0.1);
    color: var(--color-error);
    border: 1px solid rgba(239, 68, 68, 0.25);
  }
</style>
