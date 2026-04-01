<!-- SA-NUXT-04: v-html with unsanitized user content -->
<template>
  <div v-html="userComment" />
</template>

<script setup>
const props = defineProps({ userComment: String });
</script>
