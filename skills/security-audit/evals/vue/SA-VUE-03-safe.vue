<template>
  <div class="profile-links">
    <a href="#" @click.prevent="openValidatedUrl" target="_blank">Visit Website</a>
    <img alt="Avatar" ref="avatarImg" />
  </div>
</template>

<script>
function isSafeUrl(url) {
  try {
    const parsed = new URL(url, window.location.origin);
    return ['https:', 'http:'].includes(parsed.protocol) ? parsed.href : null;
  } catch {
    return null;
  }
}

export default {
  name: 'ProfileLinks',
  props: {
    userId: { type: String, required: true }
  },
  data() {
    return {
      rawUrl: '',
      rawAvatar: ''
    }
  },
  methods: {
    openValidatedUrl() {
      const safe = isSafeUrl(this.rawUrl);
      if (safe) {
        window.open(safe, '_blank', 'noopener');
      }
    },
    setAvatarSrc() {
      const safe = isSafeUrl(this.rawAvatar);
      if (safe && this.$refs.avatarImg) {
        this.$refs.avatarImg.setAttribute('src', safe);
      }
    }
  },
  async mounted() {
    const response = await fetch(`/api/users/${this.userId}`);
    const data = await response.json();
    this.rawUrl = data.website;
    this.rawAvatar = data.avatar;
    this.setAvatarSrc();
  }
}
</script>
