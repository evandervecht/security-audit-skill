<script>
  export let tag; // comes from untrusted CMS content
</script>

<svelte:element this={tag}>
  <slot />
</svelte:element>
