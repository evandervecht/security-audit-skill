<template>
  <div class="comment-section">
    <h2>User Comments</h2>
    <div class="comment-body">{{ userComment }}</div>
  </div>
</template>

<script>
export default {
  name: 'CommentDisplay',
  props: {
    commentId: { type: String, required: true }
  },
  data() {
    return {
      userComment: ''
    }
  },
  async mounted() {
    const response = await fetch(`/api/comments/${this.commentId}`);
    const data = await response.json();
    this.userComment = data.body;
  }
}
</script>
