<script>
  import { onMount } from 'svelte';
  import { getUser, login, logout } from '$lib/auth';

  // Hardware claims are in the access token JWT (RFC 9068), not the id_token.
  function decodeAccessToken(token) {
    return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
  }

  let user = $state(null);
  let loading = $state(true);
  let hardwareVerified = $derived(
    user?.access_token ? decodeAccessToken(user.access_token).hardware_verified || false : false
  );

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
  {#if hardwareVerified}
    <p><strong>Hardware Verified</strong></p>
  {/if}
  <button onclick={logout}>Sign out</button>
{:else}
  <button onclick={login}>Sign in with Vouch</button>
{/if}
