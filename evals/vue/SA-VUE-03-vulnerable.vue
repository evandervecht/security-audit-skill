<template>
  <div class="profile-links">
    <a :href ="profileUrl" target="_blank">Visit Website</a>
    <img :src ="avatarUrl" alt="Avatar" />
  </div>
</template>

<script>
export default {
  name: 'ProfileLinks',
  props: {
    userId: { type: String, required: true }
  },
  data() {
    return {
      profileUrl: '',
      avatarUrl: ''
    }
  },
  async mounted() {
    const response = await fetch(`/api/users/${this.userId}`);
    const data = await response.json();
    this.profileUrl = data.website;
    this.avatarUrl = data.avatar;
  }
}
</script>
