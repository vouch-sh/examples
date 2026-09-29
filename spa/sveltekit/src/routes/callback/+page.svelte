<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { handleCallback } from '$lib/auth';

  let error = $state(null);

  onMount(async () => {
    try {
      await handleCallback();
      goto('/');
    } catch (err) {
      console.error('Login error:', err);
      error = err.message;
    }
  });
</script>

{#if error}
  <p>Login failed: {error}. <a href="/">Try again</a></p>
{:else}
  <p>Processing login...</p>
{/if}
