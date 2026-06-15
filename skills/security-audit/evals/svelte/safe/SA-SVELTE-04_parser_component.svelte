<script>
  import { evaluate } from 'mathjs';
  export let expression;
  // safe: math-only parser, not eval; comment mentions evaluation
  function run() {
    return evaluate(expression);
  }
</script>

<button on:click={run}>Run</button>
