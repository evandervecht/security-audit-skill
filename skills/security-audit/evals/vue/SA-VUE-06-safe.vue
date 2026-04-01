<script>
import { defineStore } from 'pinia';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    isAuthenticated: false,
    userName: '',
    userRole: ''
  }),
  actions: {
    async login(credentials) {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
      });
      const data = await response.json();
      this.isAuthenticated = true;
      this.userName = data.name;
      this.userRole = data.role;
    },
    async logout() {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include'
      });
      this.isAuthenticated = false;
      this.userName = '';
      this.userRole = '';
    }
  }
});
</script>
