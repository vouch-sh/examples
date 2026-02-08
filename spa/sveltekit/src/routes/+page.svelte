<script>
  import { onMount } from 'svelte';
  import { getUser, login, logout } from '$lib/auth';

  let user = $state(null);
  let loading = $state(true);

  onMount(async () => {
    user = await getUser();
    loading = false;
  });
</script>

<h1>Vouch OIDC + SvelteKit SPA</h1>

{#if loading}
  <p>Loading...</p>
{:else if user}
  <p>Signed in as {user.profile.email}</p>
  {#if user.profile.hardware_verified}
    <p><strong>Hardware Verified</strong></p>
  {/if}
  <button onclick={logout}>Sign out</button>
{:else}
  <button onclick={login}>Sign in with Vouch</button>
{/if}
