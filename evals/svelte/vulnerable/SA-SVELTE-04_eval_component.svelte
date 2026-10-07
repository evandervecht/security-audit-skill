<script>
  export let expression;
  function run() {
    return eval(expression);
  }
</script>

<button on:click={run}>Run</button>
