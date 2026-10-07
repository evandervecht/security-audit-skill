<script>
  import DOMPurify from 'dompurify';
  export let comment;
  $: clean = DOMPurify.sanitize(comment);
</script>

<!-- safe: auto-escaped text interpolation, no raw html -->
<div>{comment}</div>
