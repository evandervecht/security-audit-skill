<!-- SA-NUXT-04: Safe — text interpolation auto-escaped by Vue -->
<template>
  <div>{{ userComment }}</div>
</template>

<script setup>
const props = defineProps({ userComment: String });
</script>
