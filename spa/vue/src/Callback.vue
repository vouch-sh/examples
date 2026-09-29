<script setup>
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { handleCallback } from './auth';

const router = useRouter();
const error = ref(null);

onMounted(async () => {
  try {
    await handleCallback();
    router.push('/');
  } catch (err) {
    console.error('Login error:', err);
    error.value = err.message;
  }
});
</script>

<template>
  <p v-if="error">Login failed: {{ error }}. <a href="/">Try again</a></p>
  <p v-else>Processing login...</p>
</template>
