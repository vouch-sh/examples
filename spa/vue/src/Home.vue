<script setup>
import { ref, onMounted } from 'vue';
import { getUser, login, logout } from './auth';

const user = ref(null);
const isLoading = ref(true);

onMounted(async () => {
  user.value = await getUser();
  isLoading.value = false;
});
</script>

<template>
  <div v-if="isLoading">Loading...</div>
  <div v-else-if="user">
    <p>Signed in as {{ user.profile.email }}</p>
    <p v-if="user.profile.hardware_verified"><strong>Hardware Verified</strong></p>
    <button @click="logout">Sign out</button>
  </div>
  <button v-else @click="login">Sign in with Vouch</button>
</template>
