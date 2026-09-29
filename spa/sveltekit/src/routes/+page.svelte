<script>
  import { onMount } from 'svelte';
  import { userManager, getUser, login, logout } from '$lib/auth';

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
  let atClaims = $derived(user?.access_token ? decodeUnverifiedForDisplay(user.access_token) : {});
  let now = $state(Math.floor(Date.now() / 1000));
  let timeLeft = $derived(Math.max((user?.expires_at ?? 0) - now, 0));

  onMount(() => {
    const unsubscribe = userManager.events.addAccessTokenExpired(async () => {
      await userManager.removeUser();
      user = null;
    });
    const timer = setInterval(() => {
      now = Math.floor(Date.now() / 1000);
    }, 1000);
    getUser().then((u) => {
      user = u;
      loading = false;
    });
    return () => {
      unsubscribe();
      clearInterval(timer);
    };
  });
</script>

<h1>Vouch OIDC + SvelteKit SPA</h1>

{#if loading}
  <p>Loading...</p>
{:else if user}
  <p>Signed in as {user.profile.email}</p>
  {#if atClaims.hardware_verified}
    <p><strong>Hardware Verified</strong></p>
  {/if}
  <div style="margin-top: 1rem; padding: 1rem; background: #f0f8ff; border-radius: 4px">
    <h3>Profile Claims</h3>
    <ul style="list-style: none; padding: 0">
      <li><strong>sub:</strong> {user.profile.sub}</li>
      <li><strong>email:</strong> {user.profile.email}</li>
      {#if user.profile.email_verified !== undefined}
        <li><strong>email_verified:</strong> {String(user.profile.email_verified)}</li>
      {/if}
      <li><strong>hardware_verified:</strong> {String(atClaims.hardware_verified || false)}</li>
      {#if atClaims.acr}
        <li><strong>acr:</strong> {atClaims.acr}</li>
      {/if}
      {#if atClaims.amr}
        <li><strong>amr:</strong> {atClaims.amr.join(', ')}</li>
      {/if}
      {#if atClaims.cnf?.jkt}
        <li><strong>DPoP-bound (cnf.jkt):</strong> {atClaims.cnf.jkt}</li>
      {/if}
    </ul>
  </div>
  <div style="margin-top: 1rem; padding: 1rem; background: #f5f5f5; border-radius: 4px">
    <h3>Token Info</h3>
    <p>Token expires in: <strong>{timeLeft}s</strong></p>
  </div>
  <div style="margin-top: 1rem">
    <button onclick={logout}>Sign out</button>
  </div>
{:else}
  <button onclick={login}>Sign in with Vouch</button>
{/if}
