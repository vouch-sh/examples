<script>
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { handleCallback } from '$lib/auth';

  onMount(async () => {
    await handleCallback();
    goto('/');
  });
</script>

<p>Processing login...</p>
