#!/bin/sh
for f in /usr/share/nginx/html/_app/immutable/**/*.js; do
  sed -i "s|__VOUCH_ISSUER__|${VOUCH_ISSUER}|g" "$f"
  sed -i "s|__VOUCH_CLIENT_ID__|${VOUCH_CLIENT_ID}|g" "$f"
  sed -i "s|__VOUCH_REDIRECT_URI__|${VOUCH_REDIRECT_URI:-http://localhost:3000/callback}|g" "$f"
done
exec "$@"
