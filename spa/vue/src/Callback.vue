<script setup>
import { onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { handleCallback } from './auth';

const router = useRouter();

onMounted(async () => {
  await handleCallback();
  router.push('/');
});
</script>

<template>
  <p>Processing login...</p>
</template>
