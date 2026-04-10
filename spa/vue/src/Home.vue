<script setup>
import { ref, computed, onMounted } from 'vue';
import { getUser, login, logout } from './auth';

// Hardware claims are in the access token JWT (RFC 9068), not the id_token.
function decodeAccessToken(token) {
  return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

const user = ref(null);
const isLoading = ref(true);
const hardwareVerified = computed(() => {
  if (!user.value?.access_token) return false;
  return decodeAccessToken(user.value.access_token).hardware_verified || false;
});

onMounted(async () => {
  user.value = await getUser();
  isLoading.value = false;
});
</script>

<template>
  <div v-if="isLoading">Loading...</div>
  <div v-else-if="user">
    <p>Signed in as {{ user.profile.email }}</p>
    <p v-if="hardwareVerified"><strong>Hardware Verified</strong></p>
    <button @click="logout">Sign out</button>
  </div>
  <button v-else @click="login">Sign in with Vouch</button>
</template>
