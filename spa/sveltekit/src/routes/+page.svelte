<script>
  import { onMount } from 'svelte';
  import { getUser, login, logout } from '$lib/auth';

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

  let user = $state(null);
  let loading = $state(true);
  let hardwareVerified = $derived(
    user?.access_token ? decodeUnverifiedForDisplay(user.access_token).hardware_verified || false : false
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
