<script setup>
import { ref, computed, onMounted } from 'vue';
import { getUser, login, logout } from './auth';

// Display only -- never an authorization decision.
//
// This decodes the access token payload WITHOUT verifying its signature. A public
// client gains nothing by verifying a token it just received over TLS from the token
// endpoint, and shipping a JOSE library to the browser to do it would teach the wrong
// lesson. The security decision belongs to the resource server, which must verify the
// signature and the audience -- see mcp/remote-server-ts, or spa/bff-express for a
// backend that holds the tokens instead.
function decodeUnverifiedForDisplay(token) {
  return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

const user = ref(null);
const isLoading = ref(true);
const hardwareVerified = computed(() => {
  if (!user.value?.access_token) return false;
  return decodeUnverifiedForDisplay(user.value.access_token).hardware_verified || false;
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
