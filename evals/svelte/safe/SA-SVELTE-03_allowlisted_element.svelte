<script>
  export let level = 1;
  const ALLOWED = { 1: 'h1', 2: 'h2', 3: 'h3' };
  $: heading = ALLOWED[level] ?? 'h2';
</script>

<!-- safe: 'this' bound to an allowlisted literal-derived value -->
<svelte:element this={heading}>
  <slot />
</svelte:element>
