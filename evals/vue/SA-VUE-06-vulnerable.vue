<script>
import { defineStore } from 'pinia';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    accessToken: '',
    refreshToken: '',
    apiKey: '',
    user: null
  }),
  actions: {
    login(response) {
      this.accessToken = response.access_token;
      this.refreshToken = response.refresh_token;
      this.apiKey = response.api_key;
      this.user = response.user;
    },
    logout() {
      this.accessToken = '';
      this.refreshToken = '';
      this.apiKey = '';
      this.user = null;
    }
  }
});
</script>
