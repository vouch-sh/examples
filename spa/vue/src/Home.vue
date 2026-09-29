<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { userManager, getUser, login, logout } from './auth';

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
const atClaims = computed(() =>
  user.value?.access_token ? decodeUnverifiedForDisplay(user.value.access_token) : {},
);
const now = ref(Math.floor(Date.now() / 1000));
const timeLeft = computed(() => Math.max((user.value?.expires_at ?? 0) - now.value, 0));
let timer;

async function onExpired() {
  await userManager.removeUser();
  user.value = null;
}

onMounted(async () => {
  userManager.events.addAccessTokenExpired(onExpired);
  timer = setInterval(() => { now.value = Math.floor(Date.now() / 1000); }, 1000);
  user.value = await getUser();
  isLoading.value = false;
});

onUnmounted(() => {
  userManager.events.removeAccessTokenExpired(onExpired);
  clearInterval(timer);
});
</script>

<template>
  <div v-if="isLoading">Loading...</div>
  <div v-else-if="user">
    <p>Signed in as {{ user.profile.email }}</p>
    <p v-if="atClaims.hardware_verified"><strong>Hardware Verified</strong></p>
    <div style="margin-top: 1rem; padding: 1rem; background: #f0f8ff; border-radius: 4px">
      <h3>Profile Claims</h3>
      <ul style="list-style: none; padding: 0">
        <li><strong>sub:</strong> {{ user.profile.sub }}</li>
        <li><strong>email:</strong> {{ user.profile.email }}</li>
        <li v-if="user.profile.email_verified !== undefined">
          <strong>email_verified:</strong> {{ String(user.profile.email_verified) }}
        </li>
        <li><strong>hardware_verified:</strong> {{ String(atClaims.hardware_verified || false) }}</li>
        <li v-if="atClaims.acr"><strong>acr:</strong> {{ atClaims.acr }}</li>
        <li v-if="atClaims.amr"><strong>amr:</strong> {{ atClaims.amr.join(', ') }}</li>
      </ul>
    </div>
    <div style="margin-top: 1rem; padding: 1rem; background: #f5f5f5; border-radius: 4px">
      <h3>Token Info</h3>
      <p>Token expires in: <strong>{{ timeLeft }}s</strong></p>
    </div>
    <div style="margin-top: 1rem">
      <button @click="logout">Sign out</button>
    </div>
  </div>
  <button v-else @click="login">Sign in with Vouch</button>
</template>
